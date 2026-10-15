"""Tests del camino batch (`src.infer`) y del loader CSV (`dataset.load_flows_csv`).

Estos fijan dos cosas:
  1. El path batch usa el MISMO encoder que el entrenamiento (invariante de paridad).
  2. Un CSV de otro exportador (CICFlowMeter, UNSW-NB15) entra al contrato por
     alias de columna, y las columnas ausentes quedan en 0 sin inventar valores.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import polars as pl
import pytest
from sklearn.pipeline import Pipeline

from src.dataset import load_flows_csv, synthetic_split
from src.infer import evaluate, score_flows
from src.pipeline import ModelBundle, build_pipeline, classifier_of, encoder_of
from src.schema import FlowFeatures, Prediction

# Formato de exportador distinto a NSL-KDD: nombres de columna con espacios.
CIC_HEADER = (
    "Flow Duration,Total Length of Fwd Packets,Total Length of Bwd Packets,"
    "Protocol,SYN-Flag Count,Flow Packet Count,Label"
)
CIC_CSV = f"""{CIC_HEADER}
1.5,48000,0,TCP,7,320,DoS Hulk
4.2,600,9000,TCP,0,12,BENIGN
0.3,45000,0,TCP,6,280,DoS Hulk
"""


@pytest.fixture
def trained() -> tuple[Pipeline, str, list[FlowFeatures]]:
    """Pipeline minimo ajustado, listo para scorear."""
    flows, labels = synthetic_split(n=200, seed=21)
    pipe = build_pipeline()
    _ = pipe.fit(flows, labels.to_numpy())
    return pipe, "random_forest", flows


def test_csv_with_cic_column_names_maps_into_contract(tmp_path: Path) -> None:
    """Given un CSV con nombres tipo CICFlowMeter, When lo cargo, Then entra al contrato."""
    path = tmp_path / "flows.csv"
    path.write_text(CIC_CSV, encoding="utf-8")

    flows, labels = load_flows_csv(path)

    assert len(flows) == 3
    assert flows[0].src_bytes == 48000
    assert flows[0].dst_bytes == 0
    assert labels is not None
    assert labels.to_list() == [1, 0, 1]


def test_csv_without_label_returns_none_labels(tmp_path: Path) -> None:
    """Given un CSV sin columna de etiqueta, When lo cargo, Then labels=None.

    Es el caso de trafico capturado en vivo: se puede puntuar pero no medir.
    """
    path = tmp_path / "flows.csv"
    path.write_text("duration,src_bytes,dst_bytes\n1.0,100,200\n", encoding="utf-8")

    flows, labels = load_flows_csv(path)

    assert labels is None
    assert len(flows) == 1
    assert flows[0].src_bytes == 100


def test_missing_columns_default_to_zero(tmp_path: Path) -> None:
    """Given un CSV con solo 3 columnas, When lo cargo, Then el resto queda en 0.

    Es la misma politica que UNSUPPORTED_BY_LIVE: no inventar la feature.
    """
    path = tmp_path / "flows.csv"
    path.write_text("src_bytes,dst_bytes\n100,200\n", encoding="utf-8")

    flows, _ = load_flows_csv(path)

    assert flows[0].serror_rate == 0.0
    assert flows[0].dst_host_count == 0


def test_empty_string_cell_becomes_zero_not_validation_error(tmp_path: Path) -> None:
    """Given una celda vacia en columna numerica, When la cargo, Then 0.0 y no crash."""
    path = tmp_path / "flows.csv"
    path.write_text("src_bytes,dst_bytes\n100,\n", encoding="utf-8")

    flows, _ = load_flows_csv(path)

    assert flows[0].dst_bytes == 0


def test_batch_scoring_uses_artefact_encoder(
    trained: tuple[Pipeline, str, list[FlowFeatures]],
) -> None:
    """Given flujos, When los scoreo en batch, Then el vector es el del encoder del artefacto.

    Este es el invariante de paridad extendido al camino batch: si alguien
    introdujera un segundo encoder aca, este test deja de pasar.
    """
    pipe, flows = trained[0], trained[2]
    sample = flows[:5]

    predictions = score_flows(sample, ModelBundle(pipe, "random_forest"))
    encoder = encoder_of(pipe)
    matrix = encoder.transform(sample)

    assert len(predictions) == 5
    expected = [bool(v) for v in classifier_of(pipe).predict(matrix)]
    assert [p.is_attack for p in predictions] == expected


def test_score_flows_returns_one_prediction_per_flow(
    trained: tuple[Pipeline, str, list[FlowFeatures]],
) -> None:
    """Given N flujos, When los scoreo, Then N predicciones en el mismo orden."""
    pipe, flows = trained[0], trained[2]
    sample = flows[:4]

    predictions = score_flows(sample, ModelBundle(pipe, "random_forest"))

    assert len(predictions) == len(sample)
    assert all(isinstance(p, Prediction) for p in predictions)


def test_evaluate_returns_all_four_metrics() -> None:
    """Given predicciones perfectas, When evalÃƒÂºo, Then las cuatro metricas en 1.0."""
    y_true = np.array([0, 1, 0, 1], dtype=np.int64)
    predictions = [
        Prediction(is_attack=False, score=0.1, model_name="rf"),
        Prediction(is_attack=True, score=0.9, model_name="rf"),
        Prediction(is_attack=False, score=0.1, model_name="rf"),
        Prediction(is_attack=True, score=0.9, model_name="rf"),
    ]

    metrics = evaluate(y_true, predictions)

    assert metrics["accuracy"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0


def test_evaluate_scores_perfect_all_benign() -> None:
    """Given un modelo que nunca dispara, When evalÃƒÂºo sobre solo benignos, Then accuracy=1.

    accuracy sola es engaÃƒÂ±osa: con desbalanceo, predecir siempre `normal` da 1.0.
    Por eso recall tambien se reporta.
    """
    y_true = np.zeros(50, dtype=np.int64)
    predictions = [Prediction(is_attack=False, score=0.0, model_name="rf") for _ in range(50)]

    metrics = evaluate(y_true, predictions)

    assert metrics["accuracy"] == 1.0
    assert metrics["recall"] == 0.0


def test_csv_labels_normalise_benign_spelling(tmp_path: Path) -> None:
    """Given etiquetas `BENIGN`/`normal` en distinta caja, When cargo, Then ambas dan 0."""
    path = tmp_path / "flows.csv"
    path.write_text("src_bytes,Label\n100,BENIGN\n200,normal\n300,DoS Hulk\n", encoding="utf-8")

    _, labels = load_flows_csv(path)

    assert labels is not None
    assert labels.to_list() == [0, 0, 1]


def test_label_column_alias_class_maps_to_label(tmp_path: Path) -> None:
    """Given la columna `class` (nomenclatura UNSW), When cargo, Then se trata como etiqueta."""
    path = tmp_path / "flows.csv"
    path.write_text("src_bytes,class\n100,Normal\n200,Attack\n", encoding="utf-8")

    _, labels = load_flows_csv(path)

    assert labels is not None
    assert labels.to_list() == [0, 1]


def test_csv_with_no_recognised_columns_yields_zero_flows(tmp_path: Path) -> None:
    """Given un CSV de columnas totalmente desconocidas, When cargo, Then flujos con todo en 0.

    No se inventa nada: el modelo recibe ceros, que es el peor caso honesto.
    """
    path = tmp_path / "flows.csv"
    path.write_text("columna_rara,otra\n1,2\n", encoding="utf-8")

    flows, _ = load_flows_csv(path)

    assert len(flows) == 1
    assert flows[0] == FlowFeatures()


def test_csv_row_count_is_preserved(tmp_path: Path) -> None:
    """Given un CSV de N filas, When cargo, Then salen exactamente N flujos."""
    path = tmp_path / "flows.csv"
    rows = "\n".join(f"{i},{i * 2}" for i in range(1, 21))
    path.write_text(f"src_bytes,dst_bytes\n{rows}\n", encoding="utf-8")

    flows, labels = load_flows_csv(path)

    assert len(flows) == 20
    assert labels is None


def test_load_flows_csv_on_headerless_file_is_handled(tmp_path: Path) -> None:
    """Given un archivo vacio, When cargo, Then no explota y devuelve listas vacias."""
    path = tmp_path / "vacio.csv"
    path.write_text("", encoding="utf-8")

    flows, labels = load_flows_csv(path)

    assert flows == []
    assert labels is None


def test_scores_are_probabilities_in_range(
    trained: tuple[Pipeline, str, list[FlowFeatures]],
) -> None:
    """Given cualquier flujo, When lo scoreo, Then score en 0..1."""
    pipe, flows = trained[0], trained[2]

    predictions = score_flows(flows[:20], ModelBundle(pipe, "random_forest"))

    assert all(0.0 <= p.score <= 1.0 for p in predictions)


def test_labels_series_type_is_int8(tmp_path: Path) -> None:
    """Given un CSV etiquetado, When cargo, Then la serie de labels es int8."""
    path = tmp_path / "flows.csv"
    path.write_text("src_bytes,Label\n100,normal\n200,Attack\n", encoding="utf-8")

    _, labels = load_flows_csv(path)

    assert labels is not None
    assert labels.dtype == pl.Int8
