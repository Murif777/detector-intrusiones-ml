"""Agregador de flujos: convierte paquetes sueltos en `FlowFeatures` por ventana.

El dataset entrena con features de *conexion*; la captura entrega *paquetes*.
Este modulo es el puente. Su salida debe encajar exactamente en
`src.schema.FlowFeatures` o el modelo no sirve en vivo.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Final, final

from .schema import PORT_TO_SERVICE, FlowFeatures

#: Ventana corta (burst/volumetrico) y ventana larga (comportamiento de host).
BURST_WINDOW_SEC: Final[float] = 2.0
HOST_WINDOW_SEC: Final[float] = 100.0

#: Gracia para descartar el ACK/FIN que llega despues de emitir un flujo.
#: Sin esto, el ultimo paquete de una conexion crea un flujo fantasma `OTH`.
LATE_PACKET_GRACE_SEC: Final[float] = 5.0


@dataclass(frozen=True, slots=True)
class Packet:
    """Paquete normalizado. Scapy se adapta a esto en `replay.py`."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    length: int
    flags: str
    timestamp: float


@dataclass(slots=True)  # MUTABLE_OK: accumulator, existe para mutar paquete a paquete
class _FlowState:
    key: tuple[str, str, int, int, str]
    first_seen: float
    last_seen: float
    packets: int = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    syn_without_reply: int = 0
    syn_seen: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    seen_dsts: set[str] = field(default_factory=set)
    closed: bool = False

    def observe(self, pkt: Packet, *, src_is_origin: bool) -> None:
        self.packets += 1
        if src_is_origin:
            self.src_bytes += pkt.length
        else:
            self.dst_bytes += pkt.length
        self.last_seen = max(self.last_seen, pkt.timestamp)
        if pkt.flags.startswith("S") and "A" not in pkt.flags:
            self.syn_seen += 1
        if pkt.flags.startswith("R"):
            self.wrong_fragment += 1
        if "F" in pkt.flags or "R" in pkt.flags:
            self.closed = True
        if "U" in pkt.flags:
            self.urgent += 1
        self.seen_dsts.add(pkt.dst_ip)

    def finalize(self) -> float:
        if self.syn_seen and self.dst_bytes == 0:
            self.syn_without_reply = self.syn_seen
        return self.syn_without_reply / max(self.packets, 1)


def harmonize_flag(*, syn_seen: int, reply_bytes: int, packets: int, reset: bool) -> str:
    """Mapea estado TCP bruto al vocabulario de flags KDD."""
    if reset:
        return "REJ"
    if syn_seen == 0:
        return "OTH"
    if reply_bytes > 0:
        return "SF"
    if packets == 1:
        return "S0"
    return "S1"


def harmonize_service(dst_port: int) -> str:
    """Mapea puerto destino a la etiqueta de servicio KDD."""
    return PORT_TO_SERVICE.get(dst_port, "other")


@final
class FlowAggregator:
    """Acumula paquetes por 5-tupla y emite flujos al cerrar la ventana.

    Uso::

        agg = FlowAggregator(window_sec=2.0)
        agg.add(pkt)
        flows = agg.close_window()
    """

    __slots__ = ("_flows", "_origin_directions", "_recently_emitted", "window_sec")

    def __init__(self, window_sec: float = BURST_WINDOW_SEC) -> None:
        self.window_sec: float = window_sec
        self._flows: dict[tuple[str, str, int, int, str], _FlowState] = {}
        self._origin_directions: dict[tuple[str, str, int, int, str], bool] = {}
        self._recently_emitted: dict[tuple[str, str, int, int, str], float] = {}

    def add(self, pkt: Packet) -> None:
        """Registra un paquete en su flujo. La primera direccion vista es el origen.

        Un flujo es UN objeto por conexion, no dos. La version anterior insertaba
        la clave inversa apuntando al mismo objeto, y como `close_window` itera
        `_flows.items()`, cada conexion bidireccional se emitia DOS veces: inflaba
        el conteo de flujos y sesgaba `dst_host_count`.
        """
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto)
        reverse = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.proto)

        if self._recently_emitted:
            cutoff = pkt.timestamp - LATE_PACKET_GRACE_SEC
            self._recently_emitted = {
                flow_key: seen
                for flow_key, seen in self._recently_emitted.items()
                if seen >= cutoff
            }

        # Un paquete que no inicia conexion y cae en un flujo recien emitido es
        # el resto (ACK/FIN) de esa conexion, no una conexion nueva. Si no se
        # descarta, aparece un flujo fantasma `OTH` de 1 paquete que el modelo
        # puede puntuar como ataque aunque el trafico sea benigno.
        if not (pkt.flags.startswith("S") and "A" not in pkt.flags):
            emitted_at = self._recently_emitted.get(key)
            if emitted_at is None:
                emitted_at = self._recently_emitted.get(reverse)
            if emitted_at is not None and pkt.timestamp - emitted_at <= LATE_PACKET_GRACE_SEC:
                return
        else:
            self._recently_emitted.pop(key, None)
            self._recently_emitted.pop(reverse, None)

        if key in self._flows:
            self._flows[key].observe(pkt, src_is_origin=self._origin_directions[key])
            return

        if reverse in self._flows:
            # Es la respuesta de una conexion ya abierta: va a esa misma entrada.
            self._flows[reverse].observe(pkt, src_is_origin=False)
            return

        # Conexion nueva: este paquete define la direccion origen.
        state = _FlowState(key=key, first_seen=pkt.timestamp, last_seen=pkt.timestamp)
        self._flows[key] = state
        self._origin_directions[key] = True
        state.observe(pkt, src_is_origin=True)

    def close_window(
        self, host_window_flows: int = 0, *, final: bool = False
    ) -> list[FlowFeatures]:
        """Emite los flujos terminados y libera su estado.

        Una conexion TCP puede durar mas que la ventana. Si se emitiera al
        cruzar el limite, la sesion quedaria partida en fragmentos y cada mitad
        pareceria trafico anomalo (`dst_bytes=0`, `count` bajisimo). Por eso un
        flujo se emite cuando CIERRA (FIN/RST) o en el flush final del stream.

        Args:
            host_window_flows: numero de flujos de la ventana de host, que
                aproxima `dst_host_count`.
            final: en el vaciado de cierre se emite tambien lo que sigue abierto.

        """
        if not self._flows:
            return []

        total = max(len(self._flows), 1)
        out: list[FlowFeatures] = []
        keep: dict[tuple[str, str, int, int, str], _FlowState] = {}

        for key, state in self._flows.items():
            if not (final or state.closed):
                keep[key] = state
                continue

            duration = max(state.last_seen - state.first_seen, 1e-6)
            serror_rate = min(state.finalize(), 1.0)
            same_srv = 1.0 if len(state.seen_dsts) == 1 and state.packets > 1 else 0.5
            out.append(
                FlowFeatures(
                    protocol_type=key[4],
                    service=harmonize_service(key[3]),
                    flag=harmonize_flag(
                        syn_seen=state.syn_seen,
                        reply_bytes=state.dst_bytes,
                        packets=state.packets,
                        reset=state.wrong_fragment > 0,
                    ),
                    duration=duration,
                    src_bytes=state.src_bytes,
                    dst_bytes=state.dst_bytes,
                    count=state.packets,
                    srv_count=state.packets,
                    wrong_fragment=state.wrong_fragment,
                    urgent=state.urgent,
                    serror_rate=serror_rate,
                    srv_serror_rate=serror_rate if state.packets > 1 else 0.0,
                    same_srv_rate=same_srv,
                    diff_srv_rate=1.0 - same_srv,
                    dst_host_count=max(host_window_flows, total),
                    dst_host_srv_count=state.packets,
                    dst_host_same_srv_rate=same_srv,
                )
            )
            # Memoriza la clave para descartar los ACK/FIN que lleguen tarde.
            self._recently_emitted[key] = state.last_seen

        self._flows = keep
        self._origin_directions = {k: v for k, v in self._origin_directions.items() if k in keep}
        return out

    def reset(self) -> None:
        """Descarta el estado de la ventana."""
        self._flows.clear()
        self._origin_directions.clear()
        self._recently_emitted.clear()

    @property
    def active_count(self) -> int:
        """Cuantos flujos siguen abiertos en la ventana en curso."""
        return len(self._flows)

    def expired(self, now: float | None = None) -> bool:
        """True si la ventana en curso supero `window_sec`."""
        if not self._flows:
            return False
        oldest = min(s.first_seen for s in self._flows.values())
        return (now or time.time()) - oldest >= self.window_sec
