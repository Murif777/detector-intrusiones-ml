"""Tests de `src.docker_control`.

El modulo se disenÃ³ para degradar con elegancia: sin daemon de Docker, cada
metodo devuelve un valor vacio o un estado honesto en vez de romperse. Estos
tests fijan ese contrato, que es lo que permite que el dashboard funcione en
un PC sin Docker (muestra los controles deshabilitados) igual que en uno con
acceso al socket.
"""

from __future__ import annotations

from pathlib import Path

from src.docker_control import (
    ATTACKS,
    DETECTOR_CONTAINER,
    VICTIM_CONTAINER,
    DockerControl,
)


def _control_at(tmp_path: Path) -> DockerControl:
    """Un control que apunta a un socket que no existe. La conexion falla."""
    return DockerControl(socket_path=str(tmp_path / "no-hay-docker.sock"))


def test_attack_catalog_matches_launcher() -> None:
    """Given el catalogo de ataques, Then cubre los cinco casos del menu."""
    codigos = [codigo for codigo, _ in ATTACKS]

    assert codigos == ["1", "2", "3", "all", "normal"]


def test_container_names_match_compose() -> None:
    """Given los nombres hardcodeados, Then coinciden con docker-compose.yml."""
    contenido = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert f"container_name: {DETECTOR_CONTAINER}" in contenido
    assert f"container_name: {VICTIM_CONTAINER}" in contenido


def test_control_degrades_without_daemon(tmp_path: Path) -> None:
    """Given que no hay daemon, When instancio, Then disponible=False y no revienta."""
    assert _control_at(tmp_path).available is False
    assert _control_at(tmp_path).error != ""


def test_status_reports_not_running_without_daemon(tmp_path: Path) -> None:
    """Given sin daemon, When consulto el estado, Then dice que no corre."""
    estado = _control_at(tmp_path).detector_status()

    assert estado.running is False


def test_launch_reports_failure_without_daemon(tmp_path: Path) -> None:
    """Given sin daemon, When intento lanzar, Then falla con mensaje, no excepcion."""
    resultado = _control_at(tmp_path).launch_attack("1")

    assert resultado.ok is False
    assert resultado.attack == "1"
    assert resultado.message != ""


def test_launch_rejects_unknown_attack(tmp_path: Path) -> None:
    """Given un codigo invalido, When intento lanzar, Then lo rechaza."""
    resultado = _control_at(tmp_path).launch_attack("invalido")

    assert resultado.ok is False


def test_tail_returns_empty_without_daemon(tmp_path: Path) -> None:
    """Given sin daemon, When pido logs, Then lista vacia y no excepcion."""
    assert _control_at(tmp_path).tail_logs() == []


def test_recent_containers_empty_without_daemon(tmp_path: Path) -> None:
    """Given sin daemon, When listo contenedores, Then lista vacia."""
    assert _control_at(tmp_path).recent_containers() == []
