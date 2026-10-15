"""Carga de NSL-KDD y capa de armonizacion de features.

Traduce las 41 columnas de NSL-KDD al contrato de `schema.FlowFeatures`. Las
columnas que el contrato no expone se descartan de forma explicita (no se
inventan), y son exactamente las que el agregador en vivo tampoco reproduce.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import numpy as np
import polars as pl

from .schema import CATEGORICAL_FEATURES, NUMERIC_FEATURES, FlowFeatures

# Probabilidad base de ataque en el dataset sintetico. No es un parametro de modelo.
SYNTHETIC_ATTACK_RATE: Final[float] = 0.5

# Etiquetas que significan "benigno", en cualquier exportador y cualquier caja.
BENIGN_LABELS: Final[frozenset[str]] = frozenset({"normal", "benign", "0", "true"})

NSL_COLUMNS: Final[tuple[str, ...]] = (
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty",
)

TRAIN_FILE: Final[str] = "KDDTrain+.txt"
TEST_FILE: Final[str] = "KDDTest+.txt"

# Columnas NSL que el contrato live no reproduce. Se documentan, no se inventan.
UNSUPPORTED_BY_LIVE: Final[tuple[str, ...]] = (
    "land",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "srv_rerror_rate",
    "srv_diff_host_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
)


def _read(path: Path) -> pl.DataFrame:
    """Lee un .txt de NSL-KDD (separado por COMAS, sin cabecera).

    El archivo original de KDD99/NSL-KDD es CSV con 43 campos: 41 features +
    `label` + `difficulty`. Polars exige un separador de un solo byte, asi que
    no se puede usar una regex para espacios.
    """
    frame = pl.read_csv(
        path,
        has_header=False,
        separator=",",
        new_columns=list(NSL_COLUMNS),
        infer_schema_length=0,
    )
    numeric = [c for c in NSL_COLUMNS if c not in ("protocol_type", "service", "flag", "label")]
    return frame.with_columns(pl.col(numeric).cast(pl.Float64))


def load_split(data_dir: Path, filename: str) -> tuple[list[FlowFeatures], pl.Series]:
    """Devuelve (flujos, etiquetas binaras donde 0=normal y 1=ataque)."""
    path = Path(data_dir) / filename
    if not path.exists() or path.stat().st_size == 0:
        return [], pl.Series([], dtype=pl.Int8)

    frame = _read(path)
    keep = [*CATEGORICAL_FEATURES, *NUMERIC_FEATURES, "label"]
    selected = frame.select(keep)
    flows = [
        FlowFeatures.model_validate({k: v for k, v in row.items() if k != "label"})
        for row in selected.drop("label").iter_rows(named=True)
    ]
    # El dtype va explicito: `.to_list()` devuelve ints de Python y `pl.Series`
    # los reinferiria como Int64, rompiendo la paridad con `load_flows_csv`.
    binary = (selected["label"] != "normal").cast(pl.Int8)
    labels = pl.Series(binary.to_list(), dtype=pl.Int8)
    return flows, labels


# Nombres alternativos de columnas segun el exportador. Los CSV de
# CICFlowMeter y los de NSL-KDD no coinciden entre si; esta tabla es la capa que
# absorbe esa diferencia sin tocar el contrato.
COLUMN_ALIASES: Final[dict[str, str]] = {
    "Flow Duration": "duration",
    "Total Length of Fwd Packets": "src_bytes",
    "Total Length of Bwd Packets": "dst_bytes",
    "Flow Length": "src_bytes",
    "Fwd Packet Length Max": "src_bytes",
    "Protocol": "protocol_type",
    "Protocol Name": "protocol_type",
    "Dst Port": "dst_port_hint",
    "Flow Flags": "flag",
    "TCP Flags": "flag",
    "SYN-Flag Count": "syn_hint",
    "Flow Packet Count": "count",
    "Total Count of Packets": "count",
    "Destination Port": "dst_port_hint",
    "Label": "label",
    "class": "label",
}


def _normalise_columns(frame: pl.DataFrame) -> pl.DataFrame:
    """Renombra columnas conocidas a los nombres del contrato. Otras pasan intactas."""
    renames = {
        raw: canonical
        for raw, canonical in COLUMN_ALIASES.items()
        if raw in frame.columns and canonical not in frame.columns
    }
    return frame.rename(renames) if renames else frame


def load_flows_csv(path: Path) -> tuple[list[FlowFeatures], pl.Series | None]:
    """Carga flujos desde un CSV con cabecera (CICFlowMeter, UNSW-NB15, etc.).

    Devuelve (flujos, labels) donde `labels` es `None` si el CSV no trae
    columna de etiqueta. Cada columna que el contrato expone toma su valor del
    CSV; las ausentes quedan en 0 por el default de `FlowFeatures`. Es la misma
    politica que `UNSUPPORTED_BY_LIVE`: no se inventan features.
    """
    if not path.exists() or path.stat().st_size == 0:
        return [], None

    frame = pl.read_csv(path, infer_schema_length=10_000)
    frame = _normalise_columns(frame)

    raw_labels = frame["label"] if "label" in frame.columns else None
    if raw_labels is not None:
        frame = frame.drop("label")

    usable = [c for c in frame.columns if c in (*NUMERIC_FEATURES, *CATEGORICAL_FEATURES)]
    rows = (
        frame.select(usable).iter_rows(named=True) if usable else [{} for _ in range(frame.height)]
    )

    flows: list[FlowFeatures] = []
    for row in rows:
        coerced = {k: _coerce(v) for k, v in row.items()}
        flows.append(FlowFeatures.model_validate(coerced))

    labels: pl.Series | None = None
    if raw_labels is not None:
        normalised = [str(v).strip().lower() for v in raw_labels.to_list()]
        binarised = [0 if value in BENIGN_LABELS else 1 for value in normalised]
        labels = pl.Series(binarised, dtype=pl.Int8)
    return flows, labels


def _coerce(value: object) -> str | float | int:
    """Normaliza un valor de CSV al tipo que `FlowFeatures` espera."""
    if isinstance(value, (int, float)):
        return value
    text = str(value).strip()
    lowered = text.lower()
    if lowered in {"nan", "none", "null", ""}:
        return 0.0
    try:
        number = float(text)
    except ValueError:
        return text
    return int(number) if number.is_integer() else number


def synthetic_split(n: int = 3000, seed: int = 42) -> tuple[list[FlowFeatures], pl.Series]:
    """Dataset sintetico con senal inyectada, para probar el pipeline sin descarga.

    NO sirve para evaluar el modelo: sirve para validar que el codigo corre de
    punta a punta. Metricas sobre datos sinteticos no significan nada.
    """
    rng = np.random.default_rng(seed)
    is_attack = rng.random(n) < SYNTHETIC_ATTACK_RATE
    flows: list[FlowFeatures] = []
    for i in range(n):
        attack = bool(is_attack[i])
        flows.append(
            FlowFeatures(
                protocol_type="tcp",
                service="http" if i % 3 else "ssh",
                flag="S0" if attack else "SF",
                duration=float(rng.exponential(1.0 if attack else 4.0)),
                src_bytes=int(rng.integers(40_000, 50_000) if attack else rng.integers(0, 900)),
                dst_bytes=int(rng.integers(0, 40) if attack else rng.integers(100, 40_000)),
                count=int(rng.integers(60, 400) if attack else rng.integers(1, 40)),
                srv_count=int(rng.integers(40, 300) if attack else rng.integers(1, 30)),
                serror_rate=float(rng.uniform(0.85, 1.0) if attack else rng.uniform(0.0, 0.15)),
                same_srv_rate=float(rng.uniform(0.1, 0.4) if attack else rng.uniform(0.8, 1.0)),
                dst_host_count=int(rng.integers(200, 255) if attack else rng.integers(1, 20)),
                dst_host_srv_count=int(rng.integers(150, 255) if attack else rng.integers(1, 20)),
                dst_host_same_srv_rate=float(
                    rng.uniform(0.0, 0.3) if attack else rng.uniform(0.8, 1.0)
                ),
            )
        )
    return flows, pl.Series(is_attack.astype(int).tolist())


def dataset_available(data_dir: Path) -> bool:
    """True si estan los dos archivos NSL-KDD descargados."""
    return (Path(data_dir) / TRAIN_FILE).exists() and (Path(data_dir) / TEST_FILE).exists()
