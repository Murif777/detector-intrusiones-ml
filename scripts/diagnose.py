"""Diagnostico: que features produce cada PCAP de demo y que score les da el modelo.

    uv run python scripts/diagnose.py

Responde una pregunta concreta antes de tocar el pipeline: si el modelo no
dispara, es porque el modelo esta equivocado, o porque el trafico generado no
se parece a los flujos que NSL-KDD le enseno?

Las detecciones salen de `src.replay.run` (el codigo de produccion). Este script
solo reconstruye las features para mostrarlas en tabla.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.packet import Packet as ScapyPacket
from scapy.utils import PcapReader

from src.features import BURST_WINDOW_SEC, HOST_WINDOW_SEC, FlowAggregator
from src.pipeline import ModelBundle, load_pipeline, predict_flow
from src.replay import StreamStats, packet_to_dict, run

console = Console()
OUT_DIR = Path("output")
SAMPLES = 3
SCENARIOS = ("syn_flood", "port_scan", "volumetric", "benign")


def _packets(path: Path) -> Iterator[ScapyPacket]:
    """Itera los paquetes crudos de un PCAP."""
    with PcapReader(str(path)) as reader:
        yield from reader


def _sample_rows(path: Path, bundle: ModelBundle) -> list[tuple[str, ...]]:
    """Primeras filas de flujo con su prediccion, para inspeccion visual."""
    burst = FlowAggregator(window_sec=BURST_WINDOW_SEC)
    host = FlowAggregator(window_sec=HOST_WINDOW_SEC)
    rows: list[tuple[str, ...]] = []

    for raw in _packets(path):
        pkt = packet_to_dict(raw)
        if pkt is None:
            continue
        burst.add(pkt)
        host.add(pkt)
        if not burst.expired(pkt.timestamp):
            continue
        for flow in burst.close_window(host_window_flows=host.active_count):
            pred = predict_flow(bundle, flow)
            rows.append(
                (
                    flow.protocol_type,
                    flow.service,
                    flow.flag,
                    f"{flow.duration:.3f}",
                    str(flow.src_bytes),
                    str(flow.dst_bytes),
                    str(flow.count),
                    f"{flow.serror_rate:.2f}",
                    f"{pred.score:.3f}",
                    "ATAQUE" if pred.is_attack else "normal",
                )
            )
            if len(rows) >= SAMPLES:
                return rows
    return rows


def profile(path: Path, bundle: ModelBundle) -> None:
    """Perfila un PCAP: tabla de features + conteos de deteccion."""
    stats: StreamStats = run(_packets(path), BURST_WINDOW_SEC, HOST_WINDOW_SEC)
    rows = _sample_rows(path, bundle)

    table = Table(title=f"{path.stem}  (flujos={stats.flows} ataques={stats.attacks})")
    for col in ("proto", "svc", "flag", "dur", "srcB", "dstB", "cnt", "serr", "score", "vered."):
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.print(table)
    console.print()


def main() -> None:
    """Perfila cada PCAP de demo contra el modelo entrenado."""
    bundle = load_pipeline()
    if bundle is None:
        console.print("[red]Sin modelo. Corre: uv run python -m src.train --data-dir data[/red]")
        return
    console.rule(f"Perfil de flujos - modelo={bundle.model_name}")

    found = False
    for name in SCENARIOS:
        path = OUT_DIR / f"{name}.pcap"
        if path.exists():
            profile(path, bundle)
            found = True
    if not found:
        hint = "[yellow]No hay PCAPs. Corre: uv run python scripts/make_demo_pcap.py[/yellow]"
        console.print(hint)


if __name__ == "__main__":
    main()
