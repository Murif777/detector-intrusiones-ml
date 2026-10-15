"""Tests de carga de datos de `src.dataset`.

El bug que fijan estos tests fue CATROSTROFICO y nadie lo noto: `read_csv` de
polars exige un separador de UN SOLO BYTE, y NSL-KDD viene separado por COMAS
con 43 campos. Con `separator=r"\\s+"` el loader reventaba, y como el camino
sintetico no lo usaba, la suite entera pasaba en verde mientras el
entrenamiento con datos reales era IMPOSIBLE de ejecutar.

Un test que solo ejercita el camino sintetico deja el camino real sin cubrir.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl
import pytest

from src.dataset import (
    NSL_COLUMNS,
    TEST_FILE,
    TRAIN_FILE,
    dataset_available,
    load_split,
)

# Linea real de NSL-KDD: 41 features + label + difficulty, separadas por COMAS.
REAL_LINE = (
    "0,tcp,ftp_data,SF,491,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,2,"
    "0.00,0.00,0.00,0.00,1.00,0.00,0.00,150,25,0.17,0.03,0.17,0.00,"
    "0.00,0.00,0.05,0.00,normal,20"
)
ATTACK_LINE = REAL_LINE.replace("normal", "neptune")


def _write_nsl(path: Path, rows: list[str]) -> None:
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_nsl_columns_match_kdd_schema() -> None:
    """Given el esquema declarado, Then tiene 43 columnas (41+label+difficulty)."""
    assert len(NSL_COLUMNS) == 43
    assert NSL_COLUMNS[-1] == "difficulty"
    assert NSL_COLUMNS[-2] == "label"


def test_load_split_reads_comma_separated_file(tmp_path: Path) -> None:
    """Given un .txt de NSL-KDD separado por COMAS, When se carga, Then no revienta.

    Este es el test de regresion del bug del separador.
    """
    path = tmp_path / "sample.txt"
    _write_nsl(path, [REAL_LINE, ATTACK_LINE])

    flows, labels = load_split(tmp_path, "sample.txt")

    assert len(flows) == 2
    assert labels.to_list() == [0, 1]


def test_load_split_maps_fields_correctly(tmp_path: Path) -> None:
    """Given una fila real, When se mapea al contrato, Then los valores coinciden."""
    path = tmp_path / "sample.txt"
    _write_nsl(path, [REAL_LINE])

    flows, _ = load_split(tmp_path, "sample.txt")

    flow = flows[0]
    assert flow.protocol_type == "tcp"
    assert flow.service == "ftp_data"
    assert flow.flag == "SF"
    assert flow.src_bytes == 491
    assert flow.dst_bytes == 0
    assert flow.count == 2
    assert flow.dst_host_count == 150


def test_load_split_binarises_labels(tmp_path: Path) -> None:
    """Given normal/neptune, When se binariza, Then 0 y 1 respectivamente."""
    path = tmp_path / "sample.txt"
    _write_nsl(path, [REAL_LINE, ATTACK_LINE, REAL_LINE, ATTACK_LINE])

    _, labels = load_split(tmp_path, "sample.txt")

    assert labels.to_list() == [0, 1, 0, 1]


def test_load_split_returns_int8_labels(tmp_path: Path) -> None:
    """Given un split, Then las labels son int8 (mismo tipo que el camino CSV)."""
    path = tmp_path / "sample.txt"
    _write_nsl(path, [REAL_LINE, ATTACK_LINE])

    _, labels = load_split(tmp_path, "sample.txt")

    assert labels.dtype == pl.Int8


def test_load_split_of_empty_file_is_empty(tmp_path: Path) -> None:
    """Given un archivo vacio, When se carga, Then listas vacias y no excepcion."""
    path = tmp_path / "vacio.txt"
    path.write_text("", encoding="utf-8")

    flows, labels = load_split(tmp_path, "vacio.txt")

    assert flows == []
    assert labels.to_list() == []


def test_dataset_available_is_false_when_missing(tmp_path: Path) -> None:
    """Given una carpeta vacia, Then dataset_available=False (no se asusta)."""
    assert dataset_available(tmp_path) is False


def test_dataset_available_is_true_when_both_present(tmp_path: Path) -> None:
    """Given ambos archivos, Then dataset_available=True."""
    (tmp_path / TRAIN_FILE).write_text(REAL_LINE, encoding="utf-8")
    (tmp_path / TEST_FILE).write_text(REAL_LINE, encoding="utf-8")

    assert dataset_available(tmp_path) is True


def test_real_dataset_loads_when_present() -> None:
    """Given el NSL-KDD real descargado, When se carga, Then sale con las filas esperadas.

    Se salta si el usuario aun no descargo el dataset: la suite tiene que quedar
    verde tanto antes como despues de la descarga.
    """
    data_dir = Path("data")
    if not dataset_available(data_dir):
        pytest.skip("NSL-KDD no descargado en data/")

    flows, labels = load_split(data_dir, TEST_FILE)

    assert len(flows) == 22544
    assert len(labels) == 22544
