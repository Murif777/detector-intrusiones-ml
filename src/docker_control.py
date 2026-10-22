"""Control de contenedores Docker desde el dashboard.

Permite lanzar ataques y leer logs del detector desde la web, sin salir del
navegador. Es una pieza de LABORATORIO: el contenedor del dashboard recibe
acceso de solo lectura al socket de Docker para poder observar y(cmd) lanzar
contenedores del mismo compose.

    from src.docker_control import DockerControl
    control = DockerControl()
    control.launch_attack("2")     # escaneo de puertos
    control.tail_logs(80)          # ultimas lineas del detector

Todo degrada con elegancia: si el socket no esta disponible (o el daemon esta
apagado), `available` es False y el dashboard muestra el panel de control
deshabilitado en vez de romperse.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final, final

from docker.errors import DockerException, NotFound

from docker import DockerClient

#: Nombres de los contenedores del compose.
DETECTOR_CONTAINER: Final[str] = "nids-detector"
VICTIM_CONTAINER: Final[str] = "nids-victim"
ATTACKER_IMAGE_ENV: Final[str] = "NIDS_ATTACKER_IMAGE"
DEFAULT_ATTACKER_IMAGE: Final[str] = (
    "ghcr.io/murif777/detector-intrusiones-ml-attacker:latest"
)
#: Socket de Docker. Se monta en el contenedor del dashboard.
DOCKER_SOCKET: Final[str] = "/var/run/docker.sock"
#: Host de la victima dentro de la red del compose.
VICTIM_HOST: Final[str] = "victim"

#: Ataques que expone `docker/attack.sh`.
ATTACKS: Final[tuple[tuple[str, str], ...]] = (
    ("1", "SYN flood"),
    ("2", "Escaneo de puertos"),
    ("3", "Inundacion HTTP"),
    ("all", "Los tres ataques"),
    ("normal", "Trafico normal"),
)


@dataclass(frozen=True, slots=True)
class DetectorStatus:
    """Estado del contenedor detector."""

    running: bool
    started_at: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class LaunchResult:
    """Resultado de intentar lanzar un ataque."""

    ok: bool
    message: str
    attack: str


def _image_tag(container: object) -> str:
    """Primera etiqueta de la imagen de un contenedor, o `?`."""
    imagen = getattr(container, "image", None)
    if isinstance(imagen, dict):
        tags = imagen.get("tags") or []
        if tags:
            return str(tags[0])
    return "?"


@final
class DockerControl:
    """Fachada sobre el socket de Docker. Todos los metodos son seguros de llamar."""

    __slots__ = ("_client", "_error")

    def __init__(self, socket_path: str | None = None) -> None:
        self._client: DockerClient | None = None
        self._error: str = ""
        try:
            base = "unix://" + (socket_path or DOCKER_SOCKET)
            self._client = DockerClient(base_url=base)
            self._client.ping()
        except DockerException as exc:
            self._client = None
            self._error = str(exc)
        except OSError as exc:
            self._client = None
            self._error = str(exc)

    @property
    def available(self) -> bool:
        """True si se puede hablar con el daemon de Docker."""
        return self._client is not None

    @property
    def error(self) -> str:
        """Motivo por el que no se pudo conectar, si aplica."""
        return self._error

    def detector_status(self) -> DetectorStatus:
        """Si el detector esta corriendo y cuando arranco."""
        if self._client is None:
            return DetectorStatus(running=False, detail="Sin acceso al socket de Docker")
        try:
            container = self._client.containers.get(DETECTOR_CONTAINER)
        except NotFound:
            return DetectorStatus(running=False, detail="El contenedor detector no existe")
        except DockerException as exc:
            return DetectorStatus(running=False, detail=str(exc))
        state = getattr(container, "status", "unknown")
        started = ""
        attrs = getattr(container, "attrs", {}) or {}
        raw_started = attrs.get("State", {}).get("StartedAt", "")
        if raw_started:
            started = raw_started[:19].replace("T", " ")
        return DetectorStatus(
            running=state == "running",
            started_at=started or None,
            detail=str(state),
        )

    def _ensure_victim(self) -> None:
        """Levanta la victima si no esta corriendo. Sin victima no hay ataque."""
        if self._client is None:
            return
        try:
            victim = self._client.containers.get(VICTIM_CONTAINER)
        except NotFound:
            self._client.containers.run(
                "nginx:alpine", name=VICTIM_CONTAINER, detach=True, remove=True
            )
            return
        if getattr(victim, "status", "") != "running":
            victim.start()

    def launch_attack(self, attack: str) -> LaunchResult:
        """Lanza un ataque desde el contenedor atacante.

        El atacante comparte el espacio de red del detector (`network_mode:
        container:<id>`), que es lo que permite que la captura vea el trafico.
        """
        if self._client is None:
            return LaunchResult(
                ok=False, attack=attack, message="Sin acceso al socket de Docker"
            )
        valid = {code for code, _ in ATTACKS}
        if attack not in valid:
            return LaunchResult(
                ok=False,
                attack=attack,
                message=f"Ataque desconocido: {attack}. Opciones: {sorted(valid)}",
            )
        try:
            detector = self._client.containers.get(DETECTOR_CONTAINER)
        except NotFound:
            return LaunchResult(
                ok=False, attack=attack, message="El contenedor detector no esta corriendo"
            )
        except DockerException as exc:
            return LaunchResult(ok=False, attack=attack, message=str(exc))

        self._ensure_victim()
        image = os.environ.get(ATTACKER_IMAGE_ENV, DEFAULT_ATTACKER_IMAGE)
        try:
            self._client.containers.run(
                image,
                # La firma del SDK es run(image, command, stdout, stderr, ...):
                # el comando va como lista, o "victim" se tomaria como stdout.
                ["/attack.sh", VICTIM_HOST],
                name=f"nids-attacker-{attack}-{os.getpid()}",
                network_mode=f"container:{detector.id}",
                environment={"ATTACK": attack},
                detach=True,
                remove=True,
            )
        except DockerException as exc:
            return LaunchResult(ok=False, attack=attack, message=str(exc))
        return LaunchResult(
            ok=True,
            attack=attack,
            message=f"Ataque '{attack}' lanzado. MirÃ¡ los logs del detector.",
        )

    def tail_logs(self, lines: int = 120) -> list[str]:
        """Ultimas lineas del log del detector. Vacio si no hay acceso."""
        if self._client is None:
            return []
        try:
            container = self._client.containers.get(DETECTOR_CONTAINER)
            raw = container.logs(tail=lines, timestamps=False)
        except (NotFound, DockerException, OSError):
            return []
        text = raw.decode("utf-8", errors="replace")
        return [line for line in text.splitlines() if line.strip()]

    def recent_containers(self, limit: int = 6) -> list[dict[str, str]]:
        """Ultimos contenedores del proyecto, para mostrar el estado del lab."""
        if self._client is None:
            return []
        try:
            containers = self._client.containers.list(
                all=True, filters={"name": "nids-"}, limit=limit
            )
        except DockerException:
            return []
        out: list[dict[str, str]] = [
            {
                "nombre": str(getattr(container, "name", "?")),
                "estado": str(getattr(container, "status", "?")),
                "imagen": _image_tag(container),
            }
            for container in containers
        ]
        return out
