"""Genera los PCAP de demostracion: 3 ataques + trafico benigno.

    uv run python scripts/make_demo_pcap.py

Por que PCAP y no captura en vivo: la captura en vivo en Windows exige Npcap
instalado y terminal de administrador. En un PC de presentacion eso es una
variable de riesgo que no vale la pena correr. Un PCAP replayado por el mismo
pipeline produce el mismo resultado siempre, en cualquier maquina, sin permisos.

Los tres ataques cubren familias distintas, que es lo que el feature set del
modelo puede (y no puede) distinguir:

  1. SYN flood   -> volumetrico. serror_rate alto, dst_bytes ~ 0.
  2. Port scan   -> baja tasa, puertos variados, resets.
  3. HTTP flood  -> mucho volumen con respuesta. bytes altos en ambos lados.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from rich.console import Console
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import PcapWriter

console = Console()

OUT_DIR: Final[Path] = Path("output")
WEB_PORT: Final[int] = 80
TLS_PORT: Final[int] = 443
DNS_PORT: Final[int] = 53
RESOLVED_PORTS: Final[int] = 100


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Un extremo de la comunicacion: ip + puerto.

    Empaquetar ip y puerto evita pasar seis parametros sueltos por funcion y
    hace explicito que `src`/`dst` son el mismo concepto con dos papeles.
    """

    ip: str
    port: int

    def at(self, port: int) -> Endpoint:
        """Mismo host, otro puerto. Para el lado que responde."""
        return Endpoint(self.ip, port)


ATTACKER: Final[Endpoint] = Endpoint("10.0.0.66", WEB_PORT)
VICTIM: Final[Endpoint] = Endpoint("10.0.0.99", WEB_PORT)
CLIENT: Final[Endpoint] = Endpoint("10.0.0.10", TLS_PORT)
SERVER: Final[Endpoint] = Endpoint("10.0.0.20", TLS_PORT)


def stamp(pkt: Any, when: float) -> Any:
    """Scapy no acepta `time=` dentro de una capa; se asigna al paquete."""
    pkt.time = when
    return pkt


def tcp(src: Endpoint, dst: Endpoint, flags: str, when: float, payload: bytes = b"") -> Any:
    """Segmento TCP con timestamp. Scapy repite mucho esto; aqui no."""
    base = IP(src=src.ip, dst=dst.ip) / TCP(sport=src.port, dport=dst.port, flags=flags)
    return stamp(base / Raw(payload) if payload else base, when)


def syn_flood(count: int = 260) -> list[Any]:
    """SYN flood / Neptune: ~260 CONEXIONES distintas, cada SYN sin respuesta.

    El perfil real de Neptune en NSL-KDD es `dst_host_count`=248, `src_bytes`=0.3
    y `serror_rate`=0.8. `dst_host_count` alto significa muchas CONEXIONES hacia
    el mismo host, no muchos paquetes en una: por eso cada SYN sale de un puerto
    origen distinto. Concentrarlos en una sola 5-tupla destruye la senal que el
    modelo aprendio.
    """
    return [
        tcp(ATTACKER.at(1024 + i), VICTIM, "S", 1.0 + i * 0.004) for i in range(count)
    ]


def port_scan(ports: int = 80) -> list[Any]:
    """Escaneo / nmap: UN puerto origen contra N puertos, todos sin respuesta.

    El perfil de escaneo en NSL-KDD es `flag=S0` (SYN sin respuesta) con
    `dst_host_count` alto: muchos flujos hacia el mismo host. La senal no es
    "muchos paquetes por flujo" sino "muchas conexiones a un mismo destino".
    """
    return [
        tcp(ATTACKER, VICTIM.at(1 + i * 13 % 1024), "S", 20.0 + i * 0.05)
        for i in range(ports)
    ]


def volumetric(connections: int = 60, per_conn: int = 8) -> list[Any]:
    """Inundacion con respuesta / perfil `satan`: muchas conexiones con carga.

    En NSL-KDD, `satan` tiene `dst_host_count`=248, `count`=219, `dst_bytes`=9.3
    y `same_srv_rate`=0.2. Es decir: muchas conexiones al mismo host, con carga
    en cada una, y trafico de ida y vuelta. A diferencia del SYN flood, aqui SI
    hay respuesta, asi que `serror_rate` queda en 0.
    """
    body = b"POST / HTTP/1.1\r\nHost: x\r\n\r\n" + b"A" * 120
    reply = b"HTTP/1.1 200 OK\r\n\r\n" + b"B" * 40
    pkts: list[Any] = []
    for c in range(connections):
        origin = ATTACKER.at(20000 + c)
        target = VICTIM.at(WEB_PORT)
        base = 50.0 + c * 0.12
        for i in range(per_conn):
            t = base + i * 0.004
            pkts.append(tcp(origin, target, "A", t, body))
            pkts.append(tcp(target, origin, "A", t + 0.002, reply))
    return pkts


def benign_sessions(sessions: int = 40) -> list[Any]:
    """Navegacion normal: handshake, peticion, respuesta y cierre.

    El payload importa: en NSL-KDD la clase `normal` promedia ~13 000 bytes de
    `src_bytes` (transferencias FTP/HTTP reales). Con respuestas de 900 B el
    trafico benigno de la demo quedaba fuera de la distribucion aprendida y el
    modelo lo marcaba como anomalo: eran 13 falsos positivos sobre 63 flujos.
    """
    request = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n" + b"q" * 400
    header = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    pkts: list[Any] = []
    for i in range(sessions):
        t = 100.0 + i * 1.2
        origin = CLIENT.at(30000 + i)
        # Respuesta grande y variable, como una pagina web real.
        response = header + b"B" * (4000 + i * 250)
        pkts.append(tcp(origin, SERVER, "S", t))
        pkts.append(tcp(SERVER, origin, "SA", t + 0.02))
        pkts.append(tcp(origin, SERVER, "A", t + 0.03, request))
        pkts.append(tcp(SERVER, origin, "A", t + 0.05, response))
        half = response[: len(response) // 2]
        pkts.append(tcp(SERVER, origin, "A", t + 0.06, half))
        pkts.append(tcp(origin, SERVER, "F", t + 0.2))
    dns = IP(src=CLIENT.ip, dst="8.8.8.8") / UDP(sport=53000, dport=DNS_PORT) / Raw(b"\x00\x01")
    pkts.append(stamp(dns, 120.0))
    return pkts


def build_sections() -> list[tuple[str, list[Any], bool]]:
    """Secciones del demo: (nombre, paquetes, es_ataque).

    Cada seccion se escribe como un PCAP aparte. Eso es lo que permite dar un
    veredicto POR ATAQUE en la presentacion, en vez de un numero agregado que
    no demuestra nada.
    """
    return [
        ("syn_flood", syn_flood(), True),
        ("port_scan", port_scan(), True),
        ("volumetric", volumetric(), True),
        ("benign", benign_sessions(), False),
    ]


def main() -> None:
    """Escribe un PCAP por seccion mas el manifiesto de ground truth."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sections = build_sections()

    total = 0
    rows: list[tuple[str, int, str]] = []
    for name, pkts, is_attack in sections:
        ordered = sorted(pkts, key=lambda p: float(p.time))
        writer = PcapWriter(str(OUT_DIR / f"{name}.pcap"), append=False)
        for pkt in ordered:
            writer.write(pkt)
        writer.close()
        total += len(ordered)
        rows.append((name, len(ordered), "ataque" if is_attack else "benign"))
        console.print(f"  {name + '.pcap':<18} {len(ordered):>4} paquetes")

    with (OUT_DIR / "demo_ground_truth.csv").open("w", newline="", encoding="utf-8") as handle:
        csv_writer = csv.writer(handle)
        csv_writer.writerow(["seccion", "paquetes", "etiqueta_real"])
        csv_writer.writerows(rows)

    console.print(f"[green]{len(sections)} PCAPs, {total} paquetes en total[/green]")


if __name__ == "__main__":
    main()
