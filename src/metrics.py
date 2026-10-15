"""Metricas de clasificacion binaria, en un solo lugar.

`src/train.py` (evaluacion offline) y `src/infer.py` (evaluacion batch sobre un
CSV) necesitan exactamente las mismas metricas. Tenerlas en dos sitios invita a
que se desincronicen y a que la demo reporte un numero distinto al informe.

Nota sobre `zero_division`: los stubs de sklearn declaran ese parametro como
`str`, pero en runtime acepta `int | float | Literal["warn"]`. El stub esta
mal; el ignore queda aislado en `_safe_prf` para no repetirlo en cada llamada.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

import numpy as np
import numpy.typing as npt
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

METRIC_KEYS: Final[tuple[str, ...]] = ("accuracy", "precision", "recall", "f1")
_ROUND: Final[int] = 4


def _safe_prf(
    fn: Callable[..., float], y_true: npt.NDArray[Any], y_pred: npt.NDArray[Any]
) -> float:
    """Llama a precision/recall/f1 con `zero_division=0` (stub de sklearn incorrecto)."""
    value: float = fn(y_true, y_pred, zero_division=0)
    return float(value)


def classification_metrics(y_true: npt.NDArray[Any], y_pred: npt.NDArray[Any]) -> dict[str, float]:
    """Accuracy, precision, recall y F1 para clasificacion binaria."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": _safe_prf(precision_score, y_true, y_pred),
        "recall": _safe_prf(recall_score, y_true, y_pred),
        "f1": _safe_prf(f1_score, y_true, y_pred),
    }


def with_roc_auc(
    metrics: dict[str, float], y_true: npt.NDArray[Any], y_score: npt.NDArray[np.float64]
) -> dict[str, float]:
    """Agrega ROC-AUC cuando hay probabilidades disponibles."""
    return {**metrics, "roc_auc": float(roc_auc_score(y_true, y_score))}


def confusion(y_true: npt.NDArray[Any], y_pred: npt.NDArray[Any]) -> npt.NDArray[np.int64]:
    """Matriz de confusion 2x2 en orden [normal, ataque]."""
    return confusion_matrix(y_true, y_pred, labels=[0, 1])


def predictions_to_array(predictions: list[Any]) -> npt.NDArray[np.int64]:
    """Convierte una lista de `Prediction` en un vector 0/1."""
    return np.array([int(p.is_attack) for p in predictions], dtype=np.int64)


def as_int64(values: list[int]) -> npt.NDArray[np.int64]:
    """Vector de enteros para comparar contra predicciones."""
    return np.asarray(values, dtype=np.int64)


#: Umbrales evaluados al entrenar. Se baja de 0.5 hacia abajo porque en un NIDS
#: el recall importa mas que la precision: una alerta de mas se revisa, un ataque
#: perdido no se recupera.
THRESHOLDS: Final[tuple[float, ...]] = (
    0.50, 0.45, 0.40, 0.35, 0.30, 0.25, 0.20, 0.15, 0.10, 0.05,
)


def threshold_sweep(
    y_true: npt.NDArray[Any], y_score: npt.NDArray[np.float64]
) -> dict[float, dict[str, float]]:
    """Evalua precision/recall/F1 para cada umbral de decision.

    Devuelve un mapa umbral -> metricas. La eleccion del umbral operativo no
    puede quedar implicita en 0.5: ese default de sklearn es el punto que
    maximiza accuracy, no el que sirve para detectar intrusiones.
    """
    out: dict[float, dict[str, float]] = {}
    for threshold in THRESHOLDS:
        y_pred = (y_score >= threshold).astype(np.int64)
        out[threshold] = classification_metrics(y_true, y_pred)
    return out
