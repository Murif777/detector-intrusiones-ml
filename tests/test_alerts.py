"""Tests del store de alertas.

El store es append-only JSONL a proposito: dos escritores concurrentes
(API + replay) corrompen un JSON reescrito completo, mientras que append de una
linea corta es atomico. Estos tests fijan ese contrato, incluida la tolerancia a
lineas corruptas.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.alerts import append_alert, make_alert, read_alerts, summary
from src.schema import Alert, FlowFeatures, Prediction

ATTACK = Prediction(is_attack=True, score=0.97, model_name="random_forest")
BENIGN = Prediction(is_attack=False, score=0.04, model_name="random_forest")


def test_make_alert_labels_attack_in_spanish() -> None:
    """Given una prediccion de ataque, When construyo la alerta, Then label=ataque."""
    alert = make_alert(ATTACK, FlowFeatures())

    assert alert.label == "ataque"
    assert alert.score == 0.97


def test_make_alert_labels_benign_in_spanish() -> None:
    """Given una prediccion normal, When construyo la alerta, Then label=normal."""
    assert make_alert(BENIGN, FlowFeatures()).label == "normal"


def test_append_creates_file_and_counts_attack(tmp_path: Path) -> None:
    """Given una alerta de ataque, When la appendo, Then queda persistida y contabilizada."""
    path = tmp_path / "alertas.jsonl"

    append_alert(make_alert(ATTACK, FlowFeatures()), path)

    assert summary(path) == {"total": 1, "ataques": 1, "normales": 0}


def test_append_accumulates_across_calls(tmp_path: Path) -> None:
    """Given varias alertas, When las appendo en secuencia, Then el store acumula.

    Append es la operacion; por eso el conteo crece y nada se sobreescribe.
    """
    path = tmp_path / "alertas.jsonl"

    append_alert(make_alert(ATTACK, FlowFeatures()), path)
    append_alert(make_alert(BENIGN, FlowFeatures()), path)
    append_alert(make_alert(ATTACK, FlowFeatures()), path)

    assert summary(path) == {"total": 3, "ataques": 2, "normales": 1}


def test_append_creates_parent_directory(tmp_path: Path) -> None:
    """Given un destino en carpeta inexistente, When appendo, Then la crea."""
    path = tmp_path / "nested" / "deep" / "alertas.jsonl"

    append_alert(make_alert(ATTACK, FlowFeatures()), path)

    assert path.exists()


def test_each_line_is_independent_json(tmp_path: Path) -> None:
    """Given dos alertas, When inspecciono el archivo, Then son dos lineas JSON.

    Esto es lo que hace append-safe: un lector puede cortar el archivo en
    cualquier linea y seguir interpretando el resto.
    """
    path = tmp_path / "alertas.jsonl"

    append_alert(make_alert(ATTACK, FlowFeatures()), path)
    append_alert(make_alert(BENIGN, FlowFeatures()), path)

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["label"] == "ataque"


def test_read_roundtrips_flow_fields(tmp_path: Path) -> None:
    """Given una alerta con flujo, When la releo, Then los campos sobreviven intactos."""
    path = tmp_path / "alertas.jsonl"
    flow = FlowFeatures(protocol_type="tcp", service="http", flag="S0", src_bytes=48000)

    append_alert(make_alert(ATTACK, flow), path)
    restored = read_alerts(path)

    assert len(restored) == 1
    assert restored[0].flow.src_bytes == 48000
    assert restored[0].flow.flag == "S0"


def test_read_skips_corrupt_line_without_failing(tmp_path: Path) -> None:
    """Given una linea corrupta entre validas, When leo, Then salteo esa linea.

    Una linea a medio escribir por un crash no debe tumbar el dashboard.
    """
    path = tmp_path / "alertas.jsonl"
    good = make_alert(ATTACK, FlowFeatures())
    line = json.dumps(good.model_dump(mode="json"))
    path.write_text(f"{line}\n{{roto\n{line}\n", encoding="utf-8")

    alerts: list[Alert] = read_alerts(path)

    assert len(alerts) == 2


def test_read_ignores_blank_lines(tmp_path: Path) -> None:
    """Given lineas vacias intercaladas, When leo, Then no cuentan como alertas."""
    path = tmp_path / "alertas.jsonl"
    line = json.dumps(make_alert(ATTACK, FlowFeatures()).model_dump(mode="json"))
    path.write_text(f"\n{line}\n\n{line}\n\n", encoding="utf-8")

    assert len(read_alerts(path)) == 2


def test_read_of_missing_file_is_empty(tmp_path: Path) -> None:
    """Given un archivo inexistente, When leo, Then lista vacia y no excepcion."""
    assert read_alerts(tmp_path / "no_existe.jsonl") == []


def test_summary_of_missing_file_is_all_zero(tmp_path: Path) -> None:
    """Given archivo inexistente, When resumo, Then ceros y no excepcion."""
    assert summary(tmp_path / "no_existe.jsonl") == {
        "total": 0,
        "ataques": 0,
        "normales": 0,
    }
