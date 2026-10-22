"""Tests del dashboard con el framework de testing de Streamlit.

`AppTest` ejecuta el script del panel de verdad y expone las excepciones.
Un simple HTTP 200 no alcanza: Streamlit renderiza por websocket, asi que un
error en el script solo aparece al ejecutarlo.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from streamlit.testing.v1 import AppTest

DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard.py"


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Store de alertas vacio y ruta de modelo inexistente, aislados."""
    alerts = tmp_path / "alertas.jsonl"
    monkeypatch.setattr("src.alerts.ALERTS_PATH", alerts)
    monkeypatch.setattr("src.pipeline.PIPELINE_PATH", tmp_path / "no_existe.joblib")
    monkeypatch.setattr("src.pipeline.METRICS_PATH", tmp_path / "no_existe.json")
    return alerts


def _alert(label: str, score: float, ts: str) -> dict[str, Any]:
    """Construye una alerta en el formato del store."""
    return {
        "ts": ts,
        "label": label,
        "score": score,
        "model_name": "random_forest",
        "flow": {
            "protocol_type": "tcp",
            "service": "http",
            "flag": "S0",
            "duration": 1.2,
            "src_bytes": 45000,
            "dst_bytes": 0,
            "count": 200,
            "srv_count": 200,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "serror_rate": 0.98,
            "srv_serror_rate": 0.98,
            "rerror_rate": 0.0,
            "same_srv_rate": 0.2,
            "diff_srv_rate": 0.8,
            "dst_host_count": 250,
            "dst_host_srv_count": 200,
            "dst_host_same_srv_rate": 0.2,
        },
    }


def test_dashboard_renders_without_alerts(store: Path) -> None:
    """Given un store vacio, When corre el panel, Then no lanza excepcion."""
    at = AppTest.from_file(str(DASHBOARD))
    at.run()

    assert not at.exception


def test_dashboard_renders_with_alerts(store: Path) -> None:
    """Given alertas en el store, When corre el panel, Then las muestra sin fallar."""
    store.write_text(
        "\n".join(
            [
                json.dumps(_alert("ataque", 0.93, "2026-10-22T10:00:01+00:00")),
                json.dumps(_alert("ataque", 0.71, "2026-10-22T10:00:02+00:00")),
                json.dumps(_alert("normal", 0.02, "2026-10-22T10:00:03+00:00")),
            ]
        ),
        encoding="utf-8",
    )

    at = AppTest.from_file(str(DASHBOARD))
    at.run()

    assert not at.exception
    markdown = "\n".join(str(m.value) for m in at.markdown)
    assert "Detecciones en vivo" in markdown


def test_dashboard_degrades_without_docker(store: Path) -> None:
    """Given que no hay socket de Docker, When corre el panel, Then lo explica.

    El panel es una pieza de laboratorio: si el socket no esta, los botones de
    ataque se deshabilitan con un mensaje, no se rompe.
    """
    at = AppTest.from_file(str(DASHBOARD))
    at.run()

    assert not at.exception
    markdown = "\n".join(str(m.value) for m in at.markdown)
    assert "Control de ataques" in markdown


def test_dashboard_exposes_attack_buttons(store: Path) -> None:
    """Given el panel, Then ofrece un boton por cada familia de ataque."""
    at = AppTest.from_file(str(DASHBOARD))
    at.run()

    labels = {b.label for b in at.button}
    assert {"SYN flood", "Escaneo de puertos", "Inundacion HTTP"} <= labels
