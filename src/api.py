"""API FastAPI del NIDS. Unica superficie HTTP del sistema.

    uv run uvicorn src.api:app --reload

Los boundaries usan Pydantic v2: lo que entra por HTTP se parsea a `FlowFeatures`
antes de tocar el modelo, y lo que sale es `Prediction`. Si no existe artefacto
entrenado, `/predict` responde 503 con instruccion accionable en vez de devolver
una puntuacion inventada.
"""

from __future__ import annotations

from functools import lru_cache
from typing import final

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from .alerts import ALERTS_PATH, append_alert, make_alert, read_alerts, summary
from .pipeline import PIPELINE_PATH, FlowRowError, ModelBundle, load_pipeline, predict_flow
from .schema import FlowFeatures, Prediction


@final
class HealthResponse(BaseModel):
    """Estado del servicio y del artefacto de inferencia."""

    model_config = ConfigDict(frozen=True)

    status: str
    model: str
    trained: bool


@final
class AlertOut(BaseModel):
    """Identificacion de la alerta emitida por una prediccion."""

    model_config = ConfigDict(frozen=True)

    ts: str
    label: str


@final
class PredictResponse(BaseModel):
    """Prediccion del modelo mas la alerta asociada."""

    model_config = ConfigDict(frozen=True)

    prediction: Prediction
    alert: AlertOut


@final
class SummaryResponse(BaseModel):
    """Conteos agregados del store de alertas."""

    model_config = ConfigDict(frozen=True)

    total: int = Field(ge=0)
    ataques: int = Field(ge=0)
    normales: int = Field(ge=0)


app = FastAPI(title="NIDS-ML", version="0.1.0", description="Deteccion de intrusiones ML")


@lru_cache(maxsize=1)
def _model() -> ModelBundle | None:
    """Carga el artefacto una sola vez y lo cachea para todo el proceso.

    Sin esto, cada request volveria a hacer `joblib.load` del modelo completo,
    que es la operacion mas cara del camino de inferencia.
    """
    return load_pipeline()


def reset_model_cache() -> None:
    """Fuerza la recarga del artefacto en el proximo request.

    Publico a proposito: los tests lo usan para no depender del orden de ejecucion.
    """
    _model.cache_clear()


def _require_model() -> ModelBundle:
    """Devuelve el artefacto completo o lanza 503 con instruccion de entrenamiento."""
    bundle = _model()
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Modelo no entrenado. Ejecuta: uv run python -m src.train --data-dir data",
        )
    return bundle


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Estado del servicio y del artefacto."""
    bundle = _model()
    return HealthResponse(
        status="ok",
        model=bundle.model_name if bundle else "sin-entrenar",
        trained=PIPELINE_PATH.exists(),
    )


@app.post("/predict", response_model=PredictResponse)
def predict(flow: FlowFeatures) -> PredictResponse:
    """Clasifica un flujo; persiste la alerta solo si es un ataque."""
    bundle = _require_model()
    try:
        prediction = predict_flow(bundle, flow)
    except FlowRowError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    alert = make_alert(prediction, flow)
    if prediction.is_attack:
        append_alert(alert)
    return PredictResponse(prediction=prediction, alert=AlertOut(ts=alert.ts, label=alert.label))


@app.get("/alerts", response_model=SummaryResponse)
def alerts() -> SummaryResponse:
    """Conteos de alertas persistidas."""
    counts: dict[str, int] = summary(ALERTS_PATH)
    return SummaryResponse(
        total=counts["total"],
        ataques=counts["ataques"],
        normales=counts["normales"],
    )


@app.get("/alerts/recent")
def recent(limit: int = 50) -> list[dict[str, object]]:
    """Ultimas alertas para el dashboard. El limite se acota a 1..500."""
    bounded = max(1, min(limit, 500))
    rows = read_alerts(ALERTS_PATH)
    return [a.model_dump(mode="json") for a in rows[-bounded:]]
