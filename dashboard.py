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

import streamlit as st

from src.alerts import ALERTS_PATH, read_alerts
from src.pipeline import METRICS_PATH, PIPELINE_PATH
from src.schema import Alert

REFRESH_SECONDS = "2s"
MAX_ROWS = 200

st.set_page_config(page_title="NIDS-ML", layout="wide")
st.title("NIDS-ML - Deteccion de intrusiones en tiempo real")
st.caption("Random Forest sobre NSL-KDD. Umbral y modelo viajan en el mismo artefacto.")


def _model_status() -> None:
    """Fila superior: estado del artefacto y conteo de alertas."""
    bundle_ok = PIPELINE_PATH.exists()
    alerts = read_alerts(ALERTS_PATH)
    attacks = sum(1 for a in alerts if a.label == "ataque")

    col_model, col_total, col_attack, col_normal = st.columns(4)
    col_model.metric("Modelo entrenado", "si" if bundle_ok else "NO")
    col_total.metric("Eventos", len(alerts))
    col_attack.metric("Ataques", attacks)
    col_normal.metric("Normales", len(alerts) - attacks)


def _training_metrics() -> None:
    """Metricas del ultimo entrenamiento, si existen."""
    if not METRICS_PATH.exists():
        return
    payload: dict[str, object] = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    results = payload.get("results")
    if not isinstance(results, dict):
        return
    st.subheader("Metricas del modelo")
    shown = {
        k: results[k]
        for k in ("accuracy", "precision", "recall", "f1", "roc_auc")
        if k in results
    }
    cols = st.columns(len(shown) or 1)
    for col, (name, value) in zip(cols, shown.items(), strict=False):
        col.metric(name, f"{value:.4f}" if isinstance(value, float) else str(value))
    if payload.get("synthetic"):
        st.warning("Entrenado con datos sinteticos: estas metricas no son evidencia.")


def _alerts_table(alerts: list[Alert]) -> None:
    """Tabla de alertas, las mas recientes primero."""
    if not alerts:
        st.info(
            "Sin alertas todavia. Lanza trafico o corre:\n\n"
            "`docker compose up --build`   o   "
            "`uv run python -m src.replay --pcap output/syn_flood.pcap`"
        )
        return
    rows = [
        {
            "hora": a.ts[11:19],
            "veredicto": a.label.upper(),
            "score": round(a.score, 3),
            "proto": a.flow.protocol_type,
            "servicio": a.flow.service,
            "flag": a.flow.flag,
            "bytes_origen": a.flow.src_bytes,
            "bytes_destino": a.flow.dst_bytes,
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
    st.caption(f"Se actualiza cada {REFRESH_SECONDS}. Deja esta pestana abierta durante el ataque.")
    _model_status()
    _alerts_table(read_alerts(ALERTS_PATH))


_model_status()
_training_metrics()
live_panel()

st.divider()
st.caption(
    f"Store: `{ALERTS_PATH}`  |  Modelo: `{PIPELINE_PATH}`  |  "
    "Escribe el NIDS, el replay o la API; este panel solo lee."
)
