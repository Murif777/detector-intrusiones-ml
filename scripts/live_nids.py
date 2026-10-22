"""Captura EN VIVO sobre una interfaz real, sin PCAP.

    uv run python scripts/live_nids.py --iface eth0 --duration 60

Es la pieza que corre dentro del contenedor NIDS de `docker-compose.yml`, donde
si existe la capacidad `NET_ADMIN` y por lo tanto `scapy.sniff()` funciona.

Diferencia con `src/replay.py`: aquel consume un iterador finito (un PCAP) y
termina; este corre contra un flujo continuo y vacia las ventanas por tiempo.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from datetime import UTC, datetime
from typing import Final

import typer
from rich.console import Console
from rich.table import Table
from scapy.packet import Packet as ScapyPacket
from scapy.sendrecv import sniff

from src.alerts import ALERTS_PATH, RUNTIME_PATH, append_alert, make_alert
from src.features import BURST_WINDOW_SEC, HOST_WINDOW_SEC, FlowAggregator
from src.pipeline import load_pipeline, predict_flow
from src.replay import packet_to_dict
from src.schema import FlowFeatures

app = typer.Typer(add_completion=False)
console = Console()

SNIFF_SLICE: Final[float] = 1.0
_STOP: Final[threading.Event] = threading.Event()


def _install_signal_handlers() -> None:
    """Corta limpio con Ctrl-C: vacia la ventana antes de salir."""

    def handler(_signum: int, _frame: object) -> None:
        _STOP.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


class LiveNIDS:
    """Clasificador en vivo: acumula paquetes y emite alertas por ventana."""

    __slots__ = (
        "_bundle",
        "_burst",
        "_host",
        "_threshold",
        "alerts",
        "flows",
        "normals",
        "packets",
    )

    def __init__(self, window: float, host_window: float, threshold: float | None = None) -> None:
        bundle = load_pipeline()
        if bundle is None:
            msg = "Modelo no entrenado. Corre: uv run python -m src.train --data-dir data"
            raise typer.BadParameter(msg)
        self._bundle = bundle
        self._burst = FlowAggregator(window_sec=window)
        self._host = FlowAggregator(window_sec=host_window)
        self._threshold = bundle.threshold if threshold is None else threshold
        self.packets = 0
        self.flows = 0
        self.alerts = 0
        self.normals = 0

    @property
    def model_name(self) -> str:
        """Nombre del modelo cargado."""
        return self._bundle.model_name

    @property
    def threshold(self) -> float:
        """Umbral efectivo de decision (artefacto o override de demo)."""
        return self._threshold

    @property
    def artifact_threshold(self) -> float:
        """Umbral con el que se entreno el artefacto, sin overrides."""
        return self._bundle.threshold

    def observe(self, raw: ScapyPacket) -> None:
        """Procesa un paquete de la interfaz."""
        pkt = packet_to_dict(raw)
        if pkt is None:
            return
        self.packets += 1
        self._burst.add(pkt)
        self._host.add(pkt)
        if self._burst.expired(pkt.timestamp):
            self.flush()

    def flush(self, *, final: bool = False) -> None:
        """Vacia la ventana y clasifica lo acumulado."""
        flows = self._burst.close_window(
            host_window_flows=self._host.active_count, final=final
        )
        self.flows += len(flows)
        for flow in flows:
            self._classify(flow)

    def _classify(self, flow: FlowFeatures) -> None:
        prediction = predict_flow(self._bundle, flow)
        # El umbral puede venir de `NIDS_THRESHOLD` (solo demo). Se reescribe la
        # prediccion para que `make_alert` derive el label del umbral efectivo.
        effective = prediction.score >= self._threshold
        prediction = prediction.model_copy(update={"is_attack": effective})
        # Se persisten TODOS los flujos: ataques y normales. El dashboard cuenta
        # "tráfico normal" como total - ataques, y sin esto siempre daba cero.
        append_alert(make_alert(prediction, flow))
        detail = (
            f"score={prediction.score:.3f} {flow.protocol_type}/{flow.service} "
            f"flag={flow.flag} src_bytes={flow.src_bytes} "
            f"serror={flow.serror_rate:.2f}"
        )
        if effective:
            self.alerts += 1
            console.print(f"[red]ATAQUE[/red] {detail}")
        else:
            self.normals += 1
            console.print(f"[green]NORMAL[/green] {detail}")


def _summary(nids: LiveNIDS, elapsed: float) -> None:
    """Imprime el resumen final de la captura."""
    table = Table(title=f"Resumen en vivo ({elapsed:.0f}s)")
    table.add_column("metrica")
    table.add_column("valor")
    table.add_row("paquetes capturados", str(nids.packets))
    table.add_row("flujos analizados", str(nids.flows))
    table.add_row("alertas emitidas", str(nids.alerts))
    table.add_row("tráfico normal", str(nids.normals))
    rate = nids.alerts / max(nids.flows, 1)
    table.add_row("tasa de alerta", f"{rate:.2%}")
    console.print(table)
    console.print(f"[dim]Eventos persistidos en {ALERTS_PATH}[/dim]")


def _env_threshold() -> float | None:
    """Lee `NIDS_THRESHOLD`: override SOLO para la demo. Vacio = sin override."""
    raw = os.environ.get("NIDS_THRESHOLD", "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        msg = f"NIDS_THRESHOLD invalido: {raw!r} (se espera un numero entre 0 y 1)"
        raise typer.BadParameter(msg) from exc
    if not 0.0 <= value <= 1.0:
        msg = f"NIDS_THRESHOLD fuera de rango: {value} (se espera 0..1)"
        raise typer.BadParameter(msg)
    return value


def _publish_runtime(nids: LiveNIDS) -> None:
    """Deja el umbral efectivo en `output/` para que el dashboard lo muestre.

    Es metadata de la corrida, no una alerta: el panel puede asi decir con
    honestidad si el detector esta usando el umbral del artefacto o uno de demo.
    """
    payload: dict[str, bool | float | str] = {
        "threshold": nids.threshold,
        "artifact_threshold": nids.artifact_threshold,
        "demo": nids.threshold != nids.artifact_threshold,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    try:
        RUNTIME_PATH.parent.mkdir(parents=True, exist_ok=True)
        RUNTIME_PATH.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    except OSError as exc:
        console.print(f"[yellow]Aviso: no se pudo escribir {RUNTIME_PATH}: {exc}[/yellow]")


@app.command()
def main(
    iface: str = typer.Option("eth0", help="Interfaz a capturar"),
    window: float = typer.Option(BURST_WINDOW_SEC, help="Ventana burst en segundos"),
    host_window: float = typer.Option(HOST_WINDOW_SEC, help="Ventana de host"),
    duration: int = typer.Option(60, help="Segundos de captura (0 = indefinido)"),
) -> None:
    """Captura en vivo y clasifica en tiempo real."""
    console.rule(f"[bold]NIDS-ML en vivo - iface={iface}[/bold]")
    _install_signal_handlers()
    nids = LiveNIDS(window, host_window, threshold=_env_threshold())
    origin = "artefacto"
    if nids.threshold != nids.artifact_threshold:
        origin = "demo, override NIDS_THRESHOLD"
    console.print(
        f"[green]modelo:[/green] {nids.model_name}   "
        f"[green]umbral:[/green] {nids.threshold:.2f} ({origin})"
    )
    _publish_runtime(nids)
    console.print(f"Capturando en {iface}... Ctrl-C para terminar.\n")

    started = time.monotonic()
    deadline = started + duration if duration else None

    def _past_deadline(_packet: ScapyPacket) -> bool:
        """Corta la captura cuando vence `--duration`."""
        return deadline is not None and time.monotonic() >= deadline

    # `sniff(timeout=)` solo corta tras un silencio: bajo flood continuo no
    # expira nunca. `stop_filter` corta al cruzar el deadline aunque los
    # paquetes no paren de llegar, y el `finally` garantiza el resumen (tambien
    # con Ctrl-C).
    try:
        while not _STOP.is_set():
            sniff(
                iface=iface,
                prn=nids.observe,
                store=False,
                timeout=SNIFF_SLICE,
                stop_filter=_past_deadline,
            )
            if deadline is not None and time.monotonic() >= deadline:
                break
    finally:
        nids.flush(final=True)
        _summary(nids, time.monotonic() - started)


if __name__ == "__main__":
    app()
