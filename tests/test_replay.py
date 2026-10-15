"""Tests del processing de stream en `src.replay`.

El bug que estos tests fijan: la ventana final no se vaciaba al terminar el
stream. Un PCAP cuyo trafico cabe dentro de `window_sec` (SYN flood corto,
escaneo rapido) producia CERO detecciones, porque `close_window()` solo se
llamaba al expirar la ventana y nunca mas. Era silencioso: el proceso terminaba
con exit code 0 y sin una sola alerta.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import IP, TCP

from src.dataset import synthetic_split
from src.features import BURST_WINDOW_SEC, FlowAggregator, Packet
from src.pipeline import build_pipeline, save_pipeline
from src.replay import StreamStats, run


@pytest.fixture
def trained_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarda un pipeline minimo donde `src.replay` lo va a encontrar."""
    flows, labels = synthetic_split(n=150, seed=5)
    pipe = build_pipeline()
    _ = pipe.fit(flows, labels.to_numpy())
    artefact = tmp_path / "pipeline.joblib"
    save_pipeline(pipe, "random_forest", path=artefact)
    monkeypatch.setattr("src.pipeline.PIPELINE_PATH", artefact)
    monkeypatch.setattr("src.alerts.ALERTS_PATH", tmp_path / "alertas.jsonl")


def _stream(*specs: tuple[float, str]) -> Iterator[Any]:
    """Construye un stream de paquetes scapy IP/TCP reales con timestamp.

    Se usan paquetes scapy de verdad, no el dataclass interno, para que el test
    ejercite tambien `packet_to_dict` (la normalizacion que ocurre en produccion).
    """
    for offset, flags in specs:
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=1000 + int(offset * 1000), dport=80, flags=flags
        )
        pkt.time = 1000.0 + offset
        yield pkt


def test_final_window_is_flushed_when_stream_ends_inside_window(
    trained_artifact: None,
) -> None:
    """Given un stream que cabe en una sola ventana, When termina, Then los flujos se procesan.

    Este es el test de regresion del bug: antes del fix devolvia flows=0 porque
    `close_window()` solo corria al expirar la ventana, y nunca mas.
    """
    stats = run(_stream((0.0, "S"), (0.1, "SA"), (0.2, "A")), window_sec=30.0, host_window=100.0)

    assert stats.packets == 3
    assert stats.flows >= 1, "la ventana final nunca se vacio: se perdian todos los flujos"


def test_flows_are_counted_not_only_attacks(trained_artifact: None) -> None:
    """Given un stream con trafico benigno, Then los flujos se cuentan aunque no alerten."""
    stats = run(_stream((0.0, "S"), (0.1, "SA"), (0.2, "A")), window_sec=30.0, host_window=100.0)

    assert stats.flows >= 1
    assert stats.attacks <= stats.flows


def test_attack_rate_is_bounded(trained_artifact: None) -> None:
    """Given cualquier stream, Then attack_rate nunca sale de 0..1."""
    stats = run(_stream(*[(i * 0.01, "S") for i in range(50)]), window_sec=5.0, host_window=100.0)

    assert 0.0 <= stats.attack_rate <= 1.0


def test_stats_preserves_total_when_nothing_detected(trained_artifact: None) -> None:
    """Given solo paquetes no-IP, Then stats queda en cero sin reventar."""
    stats = run(iter([]), window_sec=2.0, host_window=100.0)

    assert stats.packets == 0
    assert stats.flows == 0
    assert stats.attack_rate == 0.0


def test_stats_is_frozen(trained_artifact: None) -> None:
    """Given StreamStats, Then no se puede mutar (contrato de valor)."""
    stats = StreamStats(packets=1, flows=1, attacks=0)

    with pytest.raises(Exception, match=r"cannot assign|read-only|FrozenInstanceError"):
        stats.packets = 5  # pyright: ignore[reportAttributeAccessIssue]


def test_aggregator_flush_returns_flows_before_expiry() -> None:
    """Given flujos pendientes sin expirar, When cierro a mano, Then salen igual.

    El flush final es un `close_window()` explicito: por eso tiene que funcionar
    aunque la ventana no haya expirado nunca.
    """
    agg = FlowAggregator(window_sec=BURST_WINDOW_SEC)
    agg.add(Packet("10.0.0.1", "10.0.0.2", 1234, 80, "tcp", 40, "S", 1000.0))

    assert agg.expired(1000.1) is False
    assert len(agg.close_window(final=True)) == 1
