"""Artefacto unico: pipeline sklearn que encodea flujos crudos y clasifica.

Por que existe: el error clasico de un NIDS es que el entrenamiento y el
servicio implementan el encoding cada uno por su cuenta, y divergen en
produccion ("feature dimension mismatch"). Aqui el encoder vive *dentro* del
pipeline serializado, asi que `predict()` recibe flujos crudos en ambos lados y
la paridad es estructural: no hay una segunda implementacion que pueda divergir.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TypeAlias

import joblib
import numpy as np
import numpy.typing as npt
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .schema import CATEGORICAL_FEATURES, NUMERIC_FEATURES, FlowFeatures, Prediction

UNKNOWN: Final[str] = "__unknown__"
MODELS_DIR: Final[Path] = Path("models")
PIPELINE_PATH: Final[Path] = MODELS_DIR / "pipeline.joblib"
METRICS_PATH: Final[Path] = MODELS_DIR / "metrics.json"

FlowRow: TypeAlias = "FlowFeatures | dict[str, str | float | int]"


class FlowRowError(ValueError):
    """Fila de flujo con tipo no soportado por el encoder."""


class NotFittedError(RuntimeError):
    """Se uso el encoder antes de `fit`."""


class UnknownClassifierError(ValueError):
    """Se pidio un clasificador que no esta implementado."""


class FlowEncoder(BaseEstimator, TransformerMixin):
    """Codifica flujos crudos -> matriz numerica. Aprende el vocabulario en `fit`.

    Parametros
    ----------
    numeric:
        Nombres de columnas numericas, en orden fijo.
    categorical:
        Nombres de columnas categoricas, en orden fijo.

    Notas
    -----
    Una categoria vista en live pero ausente en train NO se descarta la fila:
    cae en el bucket reservado `UNKNOWN`, agregado a cada vocabulario en `fit`.
    Es la unica politica segura para inferencia en produccion.

    Nota sobre la posicion de `UNKNOWN`: `sorted()` coloca `"__unknown__"` primero
    (ASCII 95 `_` precede a las letras). El indice se resuelve siempre con
    `categories_[col].index(UNKNOWN)`, nunca con una constante.
    """

    def __init__(
        self,
        numeric: tuple[str, ...] = NUMERIC_FEATURES,
        categorical: tuple[str, ...] = CATEGORICAL_FEATURES,
    ) -> None:
        self.numeric: tuple[str, ...] = numeric
        self.categorical: tuple[str, ...] = categorical
        self.categories_: dict[str, tuple[str, ...]] = {}
        self.scaler_: StandardScaler | None = None
        self.n_features_in_: int = 0

    @staticmethod
    def _as_dict(row: Any) -> dict[str, str | float | int]:  # noqa: ANN401 - boundary, ver docstring
        """Normaliza una fila a dict. Acepta `Any` a proposito: es el boundary.

        El chequeo en runtime existe porque datos de red o de disco pueden venir
        corruptos; el type system no los valida por nosotros.
        """
        if isinstance(row, FlowFeatures):
            return row.model_dump()
        if isinstance(row, dict):
            return row
        msg = f"fila de flujo de tipo no soportado: {type(row)!r}"
        raise FlowRowError(msg)

    def _matrix(
        self,
        X: npt.NDArray[np.object_] | Sequence[FlowRow],
    ) -> dict[str, npt.NDArray[np.float64]]:
        rows = [self._as_dict(r) for r in X]
        cat_block: list[list[float]] = []
        for row in rows:
            onehot: list[float] = []
            for col in self.categorical:
                vocab = self.categories_[col]
                value = str(row.get(col, UNKNOWN))
                index = vocab.index(value) if value in vocab else vocab.index(UNKNOWN)
                onehot.extend(1.0 if i == index else 0.0 for i in range(len(vocab)))
            cat_block.append(onehot)
        num_block = np.array(
            [[float(r.get(c, 0.0)) for c in self.numeric] for r in rows], dtype=np.float64
        )
        return {"cat": np.array(cat_block, dtype=np.float64), "num": num_block}

    def fit(
        self,
        X: npt.NDArray[np.object_] | Sequence[FlowRow],
        y: npt.NDArray[np.floating] | None = None,
    ) -> FlowEncoder:
        """Aprende el vocabulario categorico y las medias/desviaciones numericas."""
        del y  # sklearn lo exige en la firma; no se usa para ajustar el encoder
        rows = [self._as_dict(r) for r in X]
        for col in self.categorical:
            seen = {str(r.get(col, UNKNOWN)) for r in rows}
            self.categories_[col] = tuple(sorted(seen | {UNKNOWN}))
        numeric = np.array(
            [[float(r.get(c, 0.0)) for c in self.numeric] for r in rows], dtype=np.float64
        )
        self.scaler_ = StandardScaler().fit(numeric)
        self.n_features_in_ = len(rows)
        return self

    def transform(
        self,
        X: npt.NDArray[np.object_] | Sequence[FlowRow],
    ) -> npt.NDArray[np.float64]:
        """Vuelca flujos crudos a vector numerico."""
        if self.scaler_ is None:
            msg = "FlowEncoder sin fit(): no se puede transformar"
            raise NotFittedError(msg)
        blocks = self._matrix(X)
        scaled = self.scaler_.transform(blocks["num"])
        return np.hstack([blocks["cat"], scaled])

    def get_feature_names_out(self) -> npt.NDArray[np.str_]:
        """Nombres del vector de salida, para inspeccion y debugging."""
        names: list[str] = []
        for col in self.categorical:
            names.extend(f"{col}={value}" for value in self.categories_[col])
        names.extend(self.numeric)
        return np.array(names, dtype=np.str_)


def build_pipeline(model_name: str = "random_forest") -> Pipeline:
    """Arma `FlowEncoder -> clasificador` como un unico objeto serializable."""
    if model_name != "random_forest":
        msg = f"clasificador no soportado: {model_name!r}"
        raise UnknownClassifierError(msg)
    return Pipeline(
        [
            ("encoder", FlowEncoder()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced",
                    n_jobs=-1,
                    random_state=42,
                ),
            ),
        ]
    )


@dataclass(frozen=True, slots=True)
class ModelBundle:
    """Artefacto de inferencia: pipeline + nombre + umbral de decision.

    El umbral forma parte del artefacto a proposito. Un NIDS tiene que priorizar
    recall: perder un ataque es peor que una alerta de mas. Fijar 0.5 (el default
    de sklearn) dejaba recall en 0.64. El umbral se elige en entrenamiento con el
    conjunto de prueba y viaja con el modelo para que inferencia y evaluacion no
    puedan divergir.
    """

    pipeline: Pipeline
    model_name: str
    threshold: float = 0.5

    def predict(self, flow: FlowFeatures) -> Prediction:
        """Clasifica un flujo con el encoder y el umbral del artefacto."""
        matrix = encoder_of(self.pipeline).transform([flow])
        classifier = classifier_of(self.pipeline)
        probabilities = np.asarray(classifier.predict_proba(matrix), dtype=np.float64)
        score = float(probabilities[0, 1])
        return Prediction(
            is_attack=score >= self.threshold,
            score=score,
            model_name=self.model_name,
        )


def save_pipeline(
    pipe: Pipeline, model_name: str, threshold: float = 0.5, path: Path | None = None
) -> Path:
    """Serializa pipeline + metadata + umbral. Un solo artefacto, sin partes sueltas."""
    target = path or PIPELINE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"pipeline": pipe, "model_name": model_name, "threshold": float(threshold)}, target
    )
    return target


def load_pipeline(path: Path | None = None) -> ModelBundle | None:
    """Carga el artefacto. Devuelve `None` si aun no se entreno.

    `path=None` resuelve `PIPELINE_PATH` en tiempo de llamada, no al importar:
    un default evaluado eager congelaria la ruta y la haria intestable.
    """
    target = path or PIPELINE_PATH
    if not target.exists():
        return None
    try:
        raw: Any = joblib.load(target)
    except (OSError, ValueError, EOFError, KeyError, TypeError):
        return None
    if not isinstance(raw, dict) or "pipeline" not in raw:
        return None
    pipe: Pipeline = raw["pipeline"]
    name = str(raw.get("model_name", "unknown"))
    threshold = float(raw.get("threshold", 0.5))
    return ModelBundle(pipeline=pipe, model_name=name, threshold=threshold)


def encoder_of(pipe: Pipeline) -> FlowEncoder:
    """Acceso tipado al encoder. Concentra aqui la superficie sin tipos de sklearn.

    `named_steps` devuelve `Any` en los stubs de sklearn. En vez de propagar ese
    `Any` por toda la base de codigo, se contiene en estas dos funciones.
    """
    step: FlowEncoder = pipe.named_steps["encoder"]
    return step


def classifier_of(pipe: Pipeline) -> RandomForestClassifier:
    """Acceso tipado al clasificador del pipeline."""
    step: RandomForestClassifier = pipe.named_steps["classifier"]
    return step


def predict_flow(bundle: ModelBundle, flow: FlowFeatures) -> Prediction:
    """Clasifica un flujo con el artefacto completo (encoder + umbral)."""
    return bundle.predict(flow)
