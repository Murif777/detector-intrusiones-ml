"""Tests de la API: boundaries Pydantic y comportamiento con/sin modelo entrenado.

El store de alertas tiene su propio archivo (`test_alerts.py`); aqui solo se
comprueba que la capa HTTP lo use bien.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest
from fastapi.testclient import TestClient
from pytest import MonkeyPatch

from src.api import app, reset_model_cache
from src.dataset import synthetic_split
from src.pipeline import build_pipeline, save_pipeline

VALID_FLOW: Final[dict[str, str | float | int]] = {
    "protocol_type": "tcp",
    "service": "http",
    "flag": "S0",
    "duration": 1.2,
    "src_bytes": 45000,
    "dst_bytes": 0,
    "count": 200,
    "serror_rate": 0.97,
}


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Cliente de test contra la app en memoria."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path: Path, monkeypatch: MonkeyPatch) -> Iterator[None]:
    """Aisla store de alertas y artefacto del modelo.

    Sin esto los tests dependen de si el usuario ya entreno o no en su maquina:
    el resultado del suite cambiaria segun el estado del filesystem.
    """
    store = tmp_path / "alertas.jsonl"
    monkeypatch.setattr("src.api.ALERTS_PATH", store)
    monkeypatch.setattr("src.alerts.ALERTS_PATH", store)
    monkeypatch.setattr("src.api.PIPELINE_PATH", tmp_path / "no_existe.joblib")
    monkeypatch.setattr("src.pipeline.PIPELINE_PATH", tmp_path / "no_existe.joblib")
    reset_model_cache()
    yield
    reset_model_cache()


@pytest.fixture
def trained_model(tmp_path: Path, monkeypatch: MonkeyPatch) -> Path:
    """Entrena un pipeline minimo real y lo expone donde la API lo busca."""
    flows, labels = synthetic_split(n=200, seed=11)
    artefact = tmp_path / "pipeline.joblib"
    pipe = build_pipeline()
    _ = pipe.fit(flows, labels.to_numpy())
    save_pipeline(pipe, "random_forest", path=artefact)
    monkeypatch.setattr("src.api.PIPELINE_PATH", artefact)
    monkeypatch.setattr("src.pipeline.PIPELINE_PATH", artefact)
    reset_model_cache()
    return artefact


def test_health_reports_untrained_when_no_artefact() -> None:
    """Given sin artefacto, When pido /health, Then trained=False y no miente."""
    with TestClient(app) as client:
        body = client.get("/health").json()

    assert body["status"] == "ok"
    assert body["trained"] is False
    assert body["model"] == "sin-entrenar"


def test_health_reports_model_name_when_artefact_exists(trained_model: Path) -> None:
    """Given artefacto presente, When /health, Then trained=True con el nombre real."""
    with TestClient(app) as client:
        body = client.get("/health").json()

    assert body["trained"] is True
    assert body["model"] == "random_forest"


def test_predict_classifies_when_model_trained(trained_model: Path) -> None:
    """Given modelo entrenado, When POST /predict, Then 200 con score en 0..1."""
    with TestClient(app) as client:
        response = client.post("/predict", json=VALID_FLOW)

    assert response.status_code == 200
    payload = response.json()
    assert 0.0 <= payload["prediction"]["score"] <= 1.0
    assert isinstance(payload["prediction"]["is_attack"], bool)


def test_predict_persists_alert_only_when_attack(trained_model: Path) -> None:
    """Given modelo entrenado, When predice normal, Then no se persiste alerta.

    Un store que crece con trafico benigno es ruido operacional: el FP rate
    se vuelve invisible en la operacion diaria.
    """
    benign = {**VALID_FLOW, "serror_rate": 0.0, "flag": "SF", "dst_bytes": 9000}

    with TestClient(app) as client:
        client.post("/predict", json=benign)

        assert client.get("/alerts").json()["total"] == 0


def test_predict_returns_503_when_model_missing(client: TestClient) -> None:
    """Given sin modelo, When POST /predict, Then 503 con instruccion, no score inventado."""
    response = client.post("/predict", json=VALID_FLOW)

    assert response.status_code == 503
    assert "src.train" in response.json()["detail"]


def test_predict_rejects_flow_with_rate_above_one() -> None:
    """Given serror_rate=5.0, When POST /predict, Then 422 por validacion Pydantic."""
    bad = {**VALID_FLOW, "serror_rate": 5.0}

    with TestClient(app) as client:
        response = client.post("/predict", json=bad)

    assert response.status_code == 422


def test_predict_rejects_unknown_field() -> None:
    """Given una clave no contemplada, When POST /predict, Then 422 (extra=forbid)."""
    bad = {**VALID_FLOW, "campo_inventado": 1}

    with TestClient(app) as client:
        response = client.post("/predict", json=bad)

    assert response.status_code == 422


def test_alerts_endpoint_returns_zeroed_counts_when_empty(client: TestClient) -> None:
    """Given store vacio, When GET /alerts, Then los tres conteos en cero."""
    body = client.get("/alerts").json()

    assert body == {"total": 0, "ataques": 0, "normales": 0}


def test_recent_returns_empty_list_when_store_empty(client: TestClient) -> None:
    """Given store vacio, When GET /alerts/recent, Then lista vacia."""
    assert client.get("/alerts/recent").json() == []
