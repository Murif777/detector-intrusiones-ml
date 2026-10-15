"""Contrato de features del NIDS: la unica definicion que comparten train y live.

Este modulo es la fuente de verdad. `src/pipeline.py` arma el vector numerico a
partir de estas listas; `src/features.py` produce objetos `FlowFeatures` con
exactamente estos campos. Si se agrega una feature aqui, ambos lados la obtienen.
"""

from __future__ import annotations

from typing import Final, final

from pydantic import BaseModel, ConfigDict, Field

# Vocabularios categoricos (KDD)
PROTOCOLS: Final[frozenset[str]] = frozenset({"tcp", "udp", "icmp"})
SERVICES: Final[frozenset[str]] = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ssh",
        "dns",
        "smtp",
        "telnet",
        "pop_3",
        "imap",
        "private",
        "other",
    }
)
FLAGS: Final[frozenset[str]] = frozenset({"SF", "S0", "S1", "S2", "REJ", "RSTO", "RSTR", "OTH"})

# Features numericas derivables de una ventana de flujo
# Las 21 restantes del NSL-KDD (num_outbound_cmds, is_host_login, dst_host_*,
# srv_*_rate, etc.) NO son derivables de paquetes crudos; se quedan en 0.
NUMERIC_FEATURES: Final[tuple[str, ...]] = (
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
)

CATEGORICAL_FEATURES: Final[tuple[str, ...]] = ("protocol_type", "service", "flag")

FEATURE_NAMES: Final[tuple[str, ...]] = CATEGORICAL_FEATURES + NUMERIC_FEATURES

# Mapeo puerto -> servicio KDD (capa de armonizacion)
PORT_TO_SERVICE: Final[dict[int, str]] = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop_3",
    143: "imap",
    443: "https",
    445: "private",
    3306: "private",
    3389: "private",
    8080: "http",
}


@final
class FlowFeatures(BaseModel):
    """Vector de features por flujo: el contrato compartido train <-> live."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol_type: str = "tcp"
    service: str = "other"
    flag: str = "SF"
    duration: float = Field(default=0.0, ge=0.0)
    src_bytes: int = Field(default=0, ge=0)
    dst_bytes: int = Field(default=0, ge=0)
    count: int = Field(default=0, ge=0)
    srv_count: int = Field(default=0, ge=0)
    wrong_fragment: int = Field(default=0, ge=0)
    urgent: int = Field(default=0, ge=0)
    hot: int = Field(default=0, ge=0)
    num_failed_logins: int = Field(default=0, ge=0)
    logged_in: int = Field(default=0, ge=0)
    num_compromised: int = Field(default=0, ge=0)
    root_shell: int = Field(default=0, ge=0)
    serror_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    srv_serror_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    rerror_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    same_srv_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    diff_srv_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    dst_host_count: int = Field(default=0, ge=0)
    dst_host_srv_count: int = Field(default=0, ge=0)
    dst_host_same_srv_rate: float = Field(default=0.0, ge=0.0, le=1.0)


@final
class Prediction(BaseModel):
    """Salida de inferencia."""

    model_config = ConfigDict(frozen=True)

    is_attack: bool
    score: float = Field(ge=0.0, le=1.0)
    model_name: str


@final
class Alert(BaseModel):
    """Evento persistido en el store de alertas."""

    model_config = ConfigDict(frozen=True)

    ts: str
    label: str
    score: float = Field(ge=0.0, le=1.0)
    model_name: str
    flow: FlowFeatures
