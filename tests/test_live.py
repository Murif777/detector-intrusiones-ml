"""Tests del camino de captura EN VIVO (`scripts.live_nids`).

Es el codigo que corre dentro del contenedor Docker. No se puede testear
`scapy.sniff()` sin una interfaz real y permisos, pero SI se puede testear la
logica que procesa cada paquete: agregacion, vaciado por ventana y clasificacion.

Se alimenta `LiveNIDS.observe()` directamente con paquetes scapy, que es
exactamente lo que hace el callback de `sniff()` en produccion.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet as ScapyPacket

from scripts.live_nids import LiveNIDS
from src.dataset import synthetic_split
from src.pipeline import build_pipeline, save_pipeline
from src.replay import StreamStats, run


@pytest.fixture
def artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Coloca un modelo entrenado donde `load_pipeline` lo busca."""
    flows, labels = synthetic_split(n=180, seed=9)
    pipe = build_pipeline()
    _ = pipe.fit(flows, labels.to_numpy())
    target = tmp_path / "pipeline.joblib"
    save_pipeline(pipe, "random_forest", path=target)
    monkeypatch.setattr("src.pipeline.PIPELINE_PATH", target)
    monkeypatch.setattr("src.alerts.ALERTS_PATH", tmp_path / "alertas.jsonl")
    yield


def _syn(sport: int, when: float) -> ScapyPacket:
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=sport, dport=80, flags="S")
    pkt.time = when
    return pkt


def test_live_nids_starts_with_zero_counters(artifact: None) -> None:
    """Given un detector nuevo, Then los contadores arrancan en cero."""
    nids = LiveNIDS(window=2.0, host_window=100.0)

    assert nids.packets == 0
    assert nids.flows == 0
    assert nids.alerts == 0


def test_observe_counts_packets(artifact: None) -> None:
    """Given paquetes IP/TCP, When los observo, Then se cuentan."""
    nids = LiveNIDS(window=30.0, host_window=100.0)

    nids.observe(_syn(1000, 1.0))
    nids.observe(_syn(1001, 1.1))

    assert nids.packets == 2


def test_observe_ignores_packets_without_ip_layer(artifact: None) -> None:
    """Given un paquete sin capa IP (p.ej. ARP), When lo observo, Then se ignora.

    En una interfaz real llegan paquetes no-IP; el detector tiene que saltarlos
    sin contarlos ni cortar la captura.
    """
    nids = LiveNIDS(window=2.0, host_window=100.0)

    nids.observe(Ether() / ARP(pdst="10.0.0.2"))  # type: ignore[no-untyped-call]

    assert nids.packets == 0


def test_flush_emits_flows_without_waiting_for_window(artifact: None) -> None:
    """Given paquetes sin expirar la ventana, When hago flush, Then se clasifican.

    El flush final es lo que garantiza que un ataque corto no se pierda al
    terminar la captura.
    """
    nids = LiveNIDS(window=30.0, host_window=100.0)
    nids.observe(_syn(1000, 1.0))
    nids.observe(_syn(1001, 1.1))

    nids.flush(final=True)

    assert nids.flows >= 1


def test_model_name_and_threshold_are_exposed(artifact: None) -> None:
    """Given el detector, Then expone modelo y umbral sin tocar privados."""
    nids = LiveNIDS(window=2.0, host_window=100.0)

    assert nids.model_name == "random_forest"
    assert 0.0 < nids.threshold <= 1.0


def test_live_and_replay_agree_on_the_same_packets(artifact: None) -> None:
    """Given los mismos paquetes, When los proceso en vivo y por replay, Then coinciden.

    Si el camino en vivo y el de replay divergieran, la demo en vivo mostraria
    numeros que el informe no respalda.
    """
    specs = [(1000 + i, 1.0 + i * 0.01, "S") for i in range(40)]

    def packets() -> Iterator[ScapyPacket]:
        for sport, when, flags in specs:
            pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=sport, dport=80, flags=flags)
            pkt.time = when
            yield pkt

    nids = LiveNIDS(window=5.0, host_window=100.0)
    for pkt in packets():
        nids.observe(pkt)
    nids.flush(final=True)

    stats: StreamStats = run(packets(), 5.0, 100.0)

    assert nids.packets == stats.packets
    assert nids.alerts == stats.attacks
