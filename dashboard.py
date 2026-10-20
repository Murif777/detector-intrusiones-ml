"""Dashboard de alertas del NIDS.

    uv run streamlit run dashboard.py

Lee `output/alertas.jsonl`, el mismo store que escriben el contenedor NIDS, el
replay y la API. Se auto-refresca cada 2 s para que durante un ataque se vean
las alertas aparecer en vivo, que es el requisito de "visualizacion de alertas
en tiempo real".

Se corre como script de Streamlit, no como modulo: Streamlit re-ejecuta el
archivo entero en cada refresco, y por eso todo es de nivel superior.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import streamlit as st

from src.alerts import ALERTS_PATH, read_alerts
from src.pipeline import METRICS_PATH, PIPELINE_PATH
from src.schema import Alert

REFRESH_SECONDS = "2s"
MAX_ROWS = 200

# Heuristica del estado del detector: una alerta con menos de 15 s de antiguedad
# significa que el NIDS sigue capturando y clasificando trafico.
FRESH_ALERT_SECONDS = 15

FLAG_LEGEND = (
    "**Leyenda:** `S0` = SYN sin respuesta · `S1` = conexión establecida · "
    + "`SF` = conexión normal (abierta y cerrada) · `REJ` = conexión rechazada. "
    + "`score` es la probabilidad de ataque (0 a 1) y `serror` la tasa de intentos fallidos."
)

st.set_page_config(page_title="NIDS-ML - Detección de intrusiones", layout="wide")
st.title("NIDS-ML · Detector de intrusiones en tiempo real")
st.markdown(
    "Este panel muestra el tráfico de la red de la demo tal como lo clasifica el detector. "
    + "Cada fila es un flujo de red ya analizado: **ATAQUE** significa que el modelo lo marcó "
    + "como malicioso. Los datos salen del store compartido y la pantalla se actualiza sola."
)


def _parse_ts(value: str) -> datetime | None:
    """Parsea un timestamp ISO-8601 del store y lo devuelve con zona horaria."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # Los timestamps del NIDS siempre llevan offset; si falta, asumimos UTC.
        return parsed.replace(tzinfo=UTC)
    return parsed


def _local_hour(value: str) -> str:
    """Convierte el timestamp UTC del JSONL a HH:MM:SS en hora local."""
    parsed = _parse_ts(value)
    if parsed is None:
        return "--:--:--"
    return parsed.astimezone().strftime("%H:%M:%S")


def _detector_status(alerts: list[Alert]) -> str:
    """Heuristica simple y visible: hay captura si la ultima alerta es reciente."""
    if not alerts:
        return "⚪ Detector detenido o sin captura reciente"
    last = _parse_ts(alerts[-1].ts)
    if last is None:
        return "⚪ Detector detenido o sin captura reciente"
    age_seconds = (datetime.now(tz=UTC) - last).total_seconds()
    if age_seconds <= FRESH_ALERT_SECONDS:
        return f"🟢 Capturando en vivo (última alerta hace {max(age_seconds, 0):.0f} s)"
    return "⚪ Detector detenido o sin captura reciente"


def _live_metrics(alerts: list[Alert]) -> None:
    """Metricas del store y estado del detector, dentro del fragment."""
    bundle_ok = PIPELINE_PATH.exists()
    attacks = sum(1 for a in alerts if a.label == "ataque")

    col_model, col_total, col_attack, col_normal = st.columns(4)
    col_model.metric("Modelo entrenado", "sí" if bundle_ok else "NO")
    col_total.metric("Eventos totales", len(alerts))
    col_attack.metric("Detectados como ataque", attacks)
    col_normal.metric("Tráfico normal", len(alerts) - attacks)

    st.markdown(_detector_status(alerts))


def _training_metrics() -> None:
    """Metricas del ultimo entrenamiento, si existen."""
    if not METRICS_PATH.exists():
        return
    payload: dict[str, object] = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    results = payload.get("results")
    if not isinstance(results, dict):
        return
    st.subheader("Métricas del modelo")
    shown = {
        k: results[k]
        for k in ("accuracy", "precision", "recall", "f1", "roc_auc")
        if k in results
    }
    cols = st.columns(len(shown) or 1)
    for col, (name, value) in zip(cols, shown.items(), strict=False):
        col.metric(name, f"{value:.4f}" if isinstance(value, float) else str(value))
    if payload.get("synthetic"):
        st.warning("Entrenado con datos sintéticos: estas métricas no son evidencia.")


def _alerts_table(alerts: list[Alert]) -> None:
    """Tabla de alertas, las mas recientes primero y con hora local."""
    if not alerts:
        st.info(
            "Sin alertas todavía. Lanza tráfico o corre:\n\n"
            + "`docker compose up --build`   o   "
            + "`uv run python -m src.replay --pcap output/syn_flood.pcap`"
        )
        return
    rows = [
        {
            "hora": _local_hour(a.ts),
            "veredicto": a.label.upper(),
            "score": round(a.score, 3),
            "protocolo": a.flow.protocol_type,
            "servicio": a.flow.service,
            "flag": a.flow.flag,
            "bytes origen": a.flow.src_bytes,
            "bytes destino": a.flow.dst_bytes,
            "paquetes": a.flow.count,
            "serror": round(a.flow.serror_rate, 2),
        }
        for a in reversed(alerts[-MAX_ROWS:])
    ]
    st.dataframe(rows, width="stretch", hide_index=True)


@st.fragment(run_every=REFRESH_SECONDS)
def live_panel() -> None:
    """Panel que se refresca solo: es lo que hace visible el 'en vivo'."""
    st.subheader("Alertas en tiempo real")
    st.caption(
        f"Última actualización: {datetime.now(tz=UTC).astimezone():%H:%M:%S} (hora local) · "
        + f"se refresca cada {REFRESH_SECONDS}."
    )
    alerts = read_alerts(ALERTS_PATH)
    _live_metrics(alerts)
    _training_metrics()
    _alerts_table(alerts)
    st.caption(FLAG_LEGEND)


live_panel()

st.divider()
st.caption(
    f"Store: `{ALERTS_PATH}`  |  Modelo: `{PIPELINE_PATH}`  |  "
    + "Escribe el NIDS, el replay o la API; este panel solo lee."
)
