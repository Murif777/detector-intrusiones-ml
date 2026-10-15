"""Test de paridad train <-> live.

Es el test mas importante del proyecto. Falla exactamente en la clase de bug
que las metricas offline no detectan: que el camino de entrenamiento y el de
servicio codifiquen features distintas. Compara vectores campo por campo, no
solo predicciones, porque dos vectores pueden diferir en una columna irrelevante
y aun asi dar la misma etiqueta.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np
import pytest
from sklearn.pipeline import Pipeline

from src.dataset import synthetic_split
from src.features import FlowAggregator, Packet
from src.pipeline import (
    FlowEncoder,
    FlowRow,
    ModelBundle,
    build_pipeline,
    classifier_of,
    encoder_of,
    predict_flow,
)
from src.schema import CATEGORICAL_FEATURES, NUMERIC_FEATURES, FlowFeatures


def _fitted_encoder() -> FlowEncoder:
    """Ajusta el encoder por el camino de entrenamiento."""
    flows, labels = synthetic_split(n=400, seed=1)
    encoder = FlowEncoder()
    encoder.fit(flows, labels.to_numpy())
    return encoder


def test_encoder_width_matches_declared_contract_when_fitted() -> None:
    """Given un encoder ajustado, When inspecciono sus nombres, Then el ancho coincide."""
    encoder = _fitted_encoder()

    expected = sum(len(encoder.categories_[c]) for c in CATEGORICAL_FEATURES) + len(
        NUMERIC_FEATURES
    )

    assert len(encoder.get_feature_names_out()) == expected


def test_transform_is_deterministic_when_same_flow_encoded_twice() -> None:
    """Given un flujo fijo, When lo encodo dos veces, Then el vector es identico."""
    encoder = _fitted_encoder()
    flows, _ = synthetic_split(n=50, seed=1)

    first = encoder.transform([flows[0]])
    second = encoder.transform([flows[0]])

    np.testing.assert_array_equal(first, second)


def test_pipeline_encoder_matches_standalone_encoder_when_serving() -> None:
    """Given el pipeline completo, When el flujo entra por el, Then su encoder interno
    produce el mismo vector que un encoder equivalente ajustado aparte.

    Es el invariante de paridad: si alguien reintroduce una segunda implementacion
    del encoding en el camino de servicio, este test deja de pasar.
    """
    flows, labels = synthetic_split(n=400, seed=1)
    pipe = build_pipeline()
    _ = pipe.fit(flows, labels.to_numpy())

    served = encoder_of(pipe)
    reference = _fitted_encoder()

    np.testing.assert_array_equal(
        served.transform([flows[7]]),
        reference.transform([flows[7]]),
    )


def test_unknown_category_lands_in_reserved_bucket_and_keeps_row() -> None:
    """Given una categoria nunca vista en train, When se codifica, Then no se descarta.

    Politica de unseen-category en produccion: bucket reservado, nunca drop.
    `FlowFeatures` acepta vocabularios abiertos a proposito (un puerto desconocido
    en live es legitimo); el encoder es quien decide a que columna cae.
    """
    encoder = _fitted_encoder()
    stranger = FlowFeatures(protocol_type="tcp", service="servicio-inexistente", flag="SF")

    matrix = encoder.transform([stranger])

    # La fila concatena un one-hot por columna categorica, en orden CATEGORICAL_FEATURES.
    order = list(CATEGORICAL_FEATURES)
    offset = sum(len(encoder.categories_[c]) for c in order[: order.index("service")])
    unknown_row_index = offset + encoder.categories_["service"].index("__unknown__")

    assert matrix.shape[0] == 1
    assert matrix[0, unknown_row_index] == 1.0


def test_prediction_reuses_encoder_inside_the_artefact() -> None:
    """Given un flujo, When se predice via el artefacto, Then usa su encoder interno."""
    flows, labels = synthetic_split(n=300, seed=2)
    pipe = build_pipeline()
    _ = pipe.fit(flows, labels.to_numpy())

    prediction = predict_flow(ModelBundle(pipe, "random_forest"), flows[0])

    encoder = encoder_of(pipe)
    classifier = classifier_of(pipe)
    expected = bool(classifier.predict(encoder.transform([flows[0]]))[0])
    assert prediction.is_attack is expected


def test_aggregated_live_flow_is_accepted_by_trained_pipeline() -> None:
    """Given flujos agregados de paquetes crudos, When se codifican, Then el modelo acepta.

    Cierra el circuito: la salida del agregador (mundo live) entra al pipeline
    (mundo train) sin error de forma ni de dimension.
    """
    flows, labels = synthetic_split(n=200, seed=3)
    pipe: Pipeline = build_pipeline()
    _ = pipe.fit(flows, labels.to_numpy())

    aggregator = FlowAggregator(window_sec=2.0)
    aggregator.add(Packet("10.0.0.5", "10.0.0.9", 4444, 80, "tcp", 120, "S", 1000.0))
    aggregated: Sequence[FlowFeatures] = aggregator.close_window(final=True)

    assert len(aggregated) == 1
    prediction = predict_flow(ModelBundle(pipe, "random_forest"), aggregated[0])
    assert 0.0 <= prediction.score <= 1.0


def _invalid_rows() -> list[FlowRow]:
    """Filas deliberadamente invalidas (fuera de tipo) para probar el rechazo.

    Se devuelve `list[Any]` porque la intencion del test ES violar el contrato;
    el encoder debe rechazarla en runtime, no el type checker.
    """
    bad: list[Any] = [42]
    return bad


def test_encoder_rejects_unsupported_row_type() -> None:
    """Given una fila que no es dict ni FlowFeatures, When la codifico, Then falla tipado."""
    encoder = _fitted_encoder()

    with pytest.raises(ValueError, match="tipo no soportado"):
        encoder.transform(_invalid_rows())
