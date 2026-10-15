"""H2: pipeline de tiempo real. PCAP o interfaz de red -> flujos -> predicion -> alerta.

    uv run python -m src.replay --pcap data/captura.pcap
    uv run python -m src.replay --iface eth0        # requiere admin + Npcap

Ventanas duales, siguiendo la practica de la literatura:
  * 2 s  -> ataques volumetricos/burst (SYN flood)
  * 100 s -> comportamiento de host (scan, brute force)
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet as ScapyPacket
from scapy.sendrecv import sniff
from scapy.utils import PcapReader

from .alerts import append_alert, make_alert
from .features import BURST_WINDOW_SEC, HOST_WINDOW_SEC, FlowAggregator, Packet
from .pipeline import ModelBundle, load_pipeline, predict_flow
from .schema import FlowFeatures

app = typer.Typer(add_completion=False)
console = Console()


def _payload_len(raw: ScapyPacket, layer: type[ScapyPacket]) -> int:
    """Bytes de PAYLOAD de la capa de transporte, sin cabeceras.

    NSL-KDD define `src_bytes` como "data bytes from source to destination": el
    payload, no el paquete completo. Un SYN puro vale 0. Usar `len(raw)`
    (cabecera IP+TCP incluidas, ~40 B) inflaba la feature y hacia que un SYN
    flood real, que en el dataset tiene `src_bytes=0`, no se pareciera a nada.
    """
    return len(raw[layer].payload)


def packet_to_dict(raw: ScapyPacket) -> Packet | None:
    """Normaliza un paquete scapy. `None` si no es IP o no trae capa de transporte."""
    if IP not in raw:
        return None
    ip = raw[IP]
    if TCP in raw:
        proto, flags, layer = "tcp", str(raw[TCP].flags), TCP
        src_port, dst_port = int(raw[TCP].sport), int(raw[TCP].dport)
    elif UDP in raw:
        proto, flags, layer = "udp", "", UDP
        src_port, dst_port = int(raw[UDP].sport), int(raw[UDP].dport)
    elif ICMP in raw:
        proto, flags, layer = "icmp", "", ICMP
        src_port, dst_port = 0, 0
    else:
        return None
    return Packet(
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        length=_payload_len(raw, layer),
        flags=flags,
        timestamp=float(raw.time),
    )


def iter_pcap(path: Path) -> Iterator[ScapyPacket]:
    """Itera un PCAP sin cargarlo completo en memoria."""
    with PcapReader(str(path)) as reader:
        yield from reader


def iter_live(iface: str) -> Iterator[ScapyPacket]:
    """Captura en vivo. Sniffing es generador: cede el control entre paquetes."""

    def only_ip(pkt: ScapyPacket) -> bool:
        return IP in pkt

    yield from sniff(iface=iface, store=True, lfilter=only_ip)


@dataclass(frozen=True, slots=True)
class StreamStats:
    """Resultado de procesar un stream de paquetes de punta a punta."""

    packets: int
    flows: int
    attacks: int

    @property
    def attack_rate(self) -> float:
        """Fraccion de flujos marcados como ataque."""
        return self.attacks / max(self.flows, 1)


def _classify(flows: Sequence[FlowFeatures], bundle: ModelBundle) -> int:
    """Clasifica los flujos de una ventana y persiste los ataques. Devuelve cuantos."""
    hits = 0
    for flow in flows:
        prediction = predict_flow(bundle, flow)
        if prediction.is_attack:
            hits += 1
            alert = make_alert(prediction, flow)
            append_alert(alert)
            detail = (
                f"score={prediction.score:.3f} {flow.protocol_type}/{flow.service} "
                f"flag={flow.flag} src_bytes={flow.src_bytes} "
                f"serror={flow.serror_rate:.2f}"
            )
            console.print(f"[red]ATAQUE[/red] {detail}")
    return hits


def run(
    source: Iterator[ScapyPacket],
    window_sec: float,
    host_window: float,
    *,
    pace: float = 0.0,
) -> StreamStats:
    """Consume la fuente, agrega por ventana y clasifica.

    Al terminar el stream se fuerza el vaciado de la ventana abierta. Sin ese
    flush final, los flujos de la ultima ventana se descartan en silencio: un
    PCAP que termina antes de `window_sec` no produciria ninguna deteccion.

    Args:
        source: paquetes a procesar.
        window_sec: ventana de burst.
        host_window: ventana de contexto de host.
        pace: segundos de pausa entre ventanas. Un PCAP se procesa en milisegundos
            y la salida aparece de golpe; con `pace` las alertas salen espaciadas
            y la reproduccion se ve como una captura en vivo. Para presentacion.

    """
    bundle = load_pipeline()
    if bundle is None:
        msg = "Modelo no entrenado. Ejecuta primero: uv run python -m src.train"
        raise typer.BadParameter(msg)

    burst = FlowAggregator(window_sec=window_sec)
    host = FlowAggregator(window_sec=host_window)
    packets = 0
    flows_total = 0
    attacks = 0

    def flush(*, final: bool = False) -> None:
        """Cierra la ventana de burst y clasifica lo acumulado.

        `final=True` emite ademas los flujos que siguen abiertos: sin eso, una
        conexion que nunca cerro (un SYN sin respuesta, tipico de un ataque)
        se perderia en silencio al terminar el stream.
        """
        nonlocal flows_total, attacks
        flows = burst.close_window(host_window_flows=host.active_count, final=final)
        flows_total += len(flows)
        attacks += _classify(flows, bundle)
        if pace > 0 and flows and not final:
            time.sleep(pace)

    for raw in source:
        pkt = packet_to_dict(raw)
        if pkt is None:
            continue
        packets += 1
        burst.add(pkt)
        host.add(pkt)
        if burst.expired(pkt.timestamp):
            flush()

    flush(final=True)  # emite tambien lo que sigue abierto
    return StreamStats(packets=packets, flows=flows_total, attacks=attacks)


@app.command()
def main(
    pcap: Path | None = typer.Option(None, "--pcap", help="PCAP a reproducir (modo offline)"),
    iface: str | None = typer.Option(None, "--iface", help="Interfaz a capturar (requiere admin)"),
    window: float = typer.Option(BURST_WINDOW_SEC, help="Ventana burst en segundos"),
    host_window: float = typer.Option(HOST_WINDOW_SEC, help="Ventana de host en segundos"),
    pace: float = typer.Option(
        0.0, help="Segundos de pausa entre ventanas (para que se vea en vivo)"
    ),
) -> None:
    """Reproduce un PCAP o captura en vivo y emite alertas."""
    console.rule("NIDS-ML | H2 replay")
    if pcap is not None and not pcap.exists():
        msg = f"PCAP no encontrado: {pcap}"
        raise typer.BadParameter(msg)
    source = iter_pcap(pcap) if pcap is not None else iter_live(iface or "")
    console.print(f"fuente={pcap or iface} ventana={window}s host={host_window}s")
    if pace > 0:
        console.print(f"[dim]ritmo: {pace}s entre ventanas (modo presentacion)[/dim]")
    stats = run(source, window, host_window, pace=pace)
    summary = (
        f"[green]paquetes={stats.packets} flujos={stats.flows} "
        f"ataques={stats.attacks} tasa={stats.attack_rate:.2%}[/green]"
    )
    console.print(summary)


if __name__ == "__main__":
    app()
