"""Captura EN VIVO sobre una interfaz real, sin PCAP.

    uv run python scripts/live_nids.py --iface eth0 --duration 60

Es la pieza que corre dentro del contenedor NIDS de `docker-compose.yml`, donde
si existe la capacidad `NET_ADMIN` y por lo tanto `scapy.sniff()` funciona.

Diferencia con `src/replay.py`: aquel consume un iterador finito (un PCAP) y
termina; este corre contra un flujo continuo y vacia las ventanas por tiempo.
"""

from __future__ import annotations

import signal
import threading
import time
from typing import Final

import typer
from rich.console import Console
from rich.table import Table
from scapy.packet import Packet as ScapyPacket
from scapy.sendrecv import sniff

from src.alerts import ALERTS_PATH, append_alert, make_alert
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

    __slots__ = ("_bundle", "_burst", "_host", "alerts", "flows", "packets")

    def __init__(self, window: float, host_window: float) -> None:
        bundle = load_pipeline()
        if bundle is None:
            msg = "Modelo no entrenado. Corre: uv run python -m src.train --data-dir data"
            raise typer.BadParameter(msg)
        self._bundle = bundle
        self._burst = FlowAggregator(window_sec=window)
        self._host = FlowAggregator(window_sec=host_window)
        self.packets = 0
        self.flows = 0
        self.alerts = 0

    @property
    def model_name(self) -> str:
        """Nombre del modelo cargado."""
        return self._bundle.model_name

    @property
    def threshold(self) -> float:
        """Umbral de decision del artefacto."""
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
        if not prediction.is_attack:
            return
        self.alerts += 1
        append_alert(make_alert(prediction, flow))
        detail = (
            f"score={prediction.score:.3f} {flow.protocol_type}/{flow.service} "
            f"flag={flow.flag} src_bytes={flow.src_bytes} "
            f"serror={flow.serror_rate:.2f}"
        )
        console.print(f"[red]ALERTA[/red] {detail}")


def _summary(nids: LiveNIDS, elapsed: float) -> None:
    """Imprime el resumen final de la captura."""
    table = Table(title=f"Resumen en vivo ({elapsed:.0f}s)")
    table.add_column("metrica")
    table.add_column("valor")
    table.add_row("paquetes capturados", str(nids.packets))
    table.add_row("flujos analizados", str(nids.flows))
    table.add_row("alertas emitidas", str(nids.alerts))
    rate = nids.alerts / max(nids.flows, 1)
    table.add_row("tasa de alerta", f"{rate:.2%}")
    console.print(table)
    console.print(f"[dim]Alertas persistidas en {ALERTS_PATH}[/dim]")


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
    nids = LiveNIDS(window, host_window)
    console.print(
        f"[green]modelo:[/green] {nids.model_name}   "
        f"[green]umbral:[/green] {nids.threshold:.2f}"
    )
    console.print(f"Capturando en {iface}... Ctrl-C para terminar.\n")

    started = time.monotonic()
    while not _STOP.is_set():
        if duration and time.monotonic() - started >= duration:
            break
        sniff(iface=iface, prn=nids.observe, store=False, timeout=SNIFF_SLICE)

    nids.flush(final=True)
    _summary(nids, time.monotonic() - started)


if __name__ == "__main__":
    app()
