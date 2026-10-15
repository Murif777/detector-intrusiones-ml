"""Store append-only de alertas en JSONL.

JSONL y no JSON porque dos escritores concurrentes (API + replay) corrompen un
JSON reescrito completo, mientras que append de una linea es atomico en Windows
y Linux para escrituras cortas.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from .schema import Alert, FlowFeatures, Prediction

ALERTS_PATH: Final[Path] = Path("output/alertas.jsonl")


def make_alert(prediction: Prediction, flow: FlowFeatures, ts: str | None = None) -> Alert:
    """Construye el evento con timestamp UTC ISO-8601."""
    stamp = ts or datetime.now(UTC).isoformat()
    return Alert(
        ts=stamp,
        label="ataque" if prediction.is_attack else "normal",
        score=prediction.score,
        model_name=prediction.model_name,
        flow=flow,
    )


def append_alert(alert: Alert, path: Path | None = None) -> Path:
    """Agrega una alerta. Crea el archivo y su carpeta si no existen."""
    target = path or ALERTS_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(alert.model_dump(mode="json"), separators=(",", ":"))
    with target.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return target


def read_alerts(path: Path | None = None) -> list[Alert]:
    """Lee todas las alertas. Una linea corrupta se salta, no tumba la lectura."""
    target = path or ALERTS_PATH
    if not target.exists():
        return []
    alerts: list[Alert] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            alerts.append(Alert.model_validate_json(line))
        except ValueError:
            continue
    return alerts


def summary(path: Path | None = None) -> dict[str, int]:
    """Conteos para el dashboard."""
    alerts = read_alerts(path)
    attacks = sum(1 for a in alerts if a.label == "ataque")
    return {"total": len(alerts), "ataques": attacks, "normales": len(alerts) - attacks}
