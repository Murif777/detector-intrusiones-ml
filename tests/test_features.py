"""Tests del agregador de flujos: la capa puente entre paquetes y modelo."""

from __future__ import annotations

from src.features import FlowAggregator, Packet, harmonize_flag, harmonize_service


def _syn(src_port: int, ts: float, length: int = 120) -> Packet:
    return Packet("10.0.0.1", "10.0.0.2", src_port, 80, "tcp", length, "S", ts)


def test_port_maps_to_kdd_service_label() -> None:
    """Given un puerto conocido, When se armoniza, Then devuelve la etiqueta KDD."""
    assert harmonize_service(80) == "http"
    assert harmonize_service(443) == "https"


def test_unknown_port_falls_back_to_other() -> None:
    """Given un puerto fuera del catalogo, When se armoniza, Then es `other`."""
    assert harmonize_service(65000) == "other"


def test_syn_without_reply_is_flag_s0() -> None:
    """Given un SYN sin respuesta, When se armoniza el flag, Then es S0."""
    assert harmonize_flag(syn_seen=1, reply_bytes=0, packets=1, reset=False) == "S0"


def test_completed_handshake_is_flag_sf() -> None:
    """Given SYN con respuesta, When se armoniza el flag, Then es SF."""
    assert harmonize_flag(syn_seen=1, reply_bytes=400, packets=6, reset=False) == "SF"


def test_reset_is_flag_rej() -> None:
    """Given un RST, When se armoniza el flag, Then es REJ."""
    assert harmonize_flag(syn_seen=1, reply_bytes=0, packets=2, reset=True) == "REJ"


def test_no_syn_is_flag_oth() -> None:
    """Given trafico sin SYN, When se armoniza el flag, Then es OTH."""
    assert harmonize_flag(syn_seen=0, reply_bytes=100, packets=3, reset=False) == "OTH"


def test_aggregator_emits_one_flow_per_five_tuple() -> None:
    """Given dos paquetes del mismo flujo, When cierro la ventana, Then hay un flujo."""
    aggregator = FlowAggregator(window_sec=2.0)
    aggregator.add(_syn(4444, 1000.0))
    aggregator.add(_syn(4444, 1001.0))

    flows = aggregator.close_window(final=True)

    assert len(flows) == 1
    assert flows[0].count == 2
    assert flows[0].src_bytes == 240


def test_distinct_source_ports_produce_distinct_flows() -> None:
    """Given dos 5-tuplas distintas, When cierro la ventana, Then son dos flujos."""
    aggregator = FlowAggregator(window_sec=2.0)
    aggregator.add(_syn(4444, 1000.0))
    aggregator.add(_syn(5555, 1000.5))

    flows = aggregator.close_window(final=True)

    assert len(flows) == 2


def test_reply_packets_accumulate_into_origin_flow() -> None:
    """Given un SYN y su respuesta inversa, When cierro, Then el flujo tiene ambos lados.

    Sin esto, un scan pareceria trafico sin respuesta y `dst_bytes` seria siempre 0.
    """
    aggregator = FlowAggregator(window_sec=2.0)
    aggregator.add(Packet("10.0.0.1", "10.0.0.2", 4444, 80, "tcp", 120, "S", 1000.0))
    aggregator.add(Packet("10.0.0.2", "10.0.0.1", 80, 4444, "tcp", 300, "SA", 1000.1))

    flows = aggregator.close_window(final=True)

    assert flows[0].dst_bytes == 300
    assert flows[0].flag == "SF"


def test_open_flow_is_carried_when_window_closes() -> None:
    """Given un flujo SIN cerrar, When cruza la ventana, Then sigue abierto.

    Emitirlo a mitad de sesion lo partiria en fragmentos y cada mitad pareceria
    trafico anomalo. El flush final es quien lo emite completo.
    """
    aggregator = FlowAggregator(window_sec=2.0)
    aggregator.add(_syn(4444, 1000.0))

    emitted = aggregator.close_window()

    assert emitted == []
    assert aggregator.active_count == 1


def test_closed_flow_is_emitted_and_state_released() -> None:
    """Given un flujo que cerro con FIN, When cruza la ventana, Then se emite y se libera."""
    aggregator = FlowAggregator(window_sec=2.0)
    aggregator.add(_syn(4444, 1000.0))
    aggregator.add(Packet("10.0.0.1", "10.0.0.2", 4444, 80, "tcp", 40, "F", 1000.2))

    emitted = aggregator.close_window()

    assert len(emitted) == 1
    assert aggregator.active_count == 0
    assert aggregator.close_window(final=True) == []


def test_final_flush_emits_flows_still_open() -> None:
    """Given flujos abiertos al terminar el stream, When flush final, Then se emiten.

    Sin esto, un SYN sin respuesta (tipico de un ataque) se perderia en silencio.
    """
    aggregator = FlowAggregator(window_sec=2.0)
    aggregator.add(_syn(4444, 1000.0))

    emitted = aggregator.close_window(final=True)

    assert len(emitted) == 1
    assert aggregator.active_count == 0


def test_expired_is_false_when_window_within_limit() -> None:
    """Given un flujo reciente, When consulto expiracion, Then no ha expirado."""
    aggregator = FlowAggregator(window_sec=5.0)
    aggregator.add(_syn(4444, 1000.0))

    assert aggregator.expired(1001.0) is False


def test_expired_is_true_when_window_exceeded() -> None:
    """Given un flujo viejo, When consulto expiracion, Then si expiro."""
    aggregator = FlowAggregator(window_sec=5.0)
    aggregator.add(_syn(4444, 1000.0))

    assert aggregator.expired(1020.0) is True
