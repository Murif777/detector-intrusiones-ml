"""Perfila los ataques reales de NSL-KDD para saber que debe generar el demo.

    uv run python scripts/profile_kdd.py --data-dir data

Responde: que valores toman `count`, `src_bytes`, `serror_rate`, `dst_host_count`
en cada familia de ataque? Sin ese ground truth, uno genera PCAPs que el modelo
no puede reconocer y concluye (mal) que el modelo falla.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import polars as pl

from src.dataset import NSL_COLUMNS, TRAIN_FILE

FEATURES = [
    "count",
    "srv_count",
    "src_bytes",
    "dst_bytes",
    "serror_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "same_srv_rate",
]


def main() -> None:
    """Imprime media/min/max de las features clave por familia de ataque."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args()

    path = args.data_dir / TRAIN_FILE
    frame = pl.read_csv(
        path,
        has_header=False,
        separator=",",
        new_columns=list(NSL_COLUMNS),
        infer_schema_length=0,
    )
    numeric = [c for c in NSL_COLUMNS if c not in ("protocol_type", "service", "flag", "label")]
    frame = frame.with_columns(pl.col(numeric).cast(pl.Float64))

    families = ["neptune", "normal", "nmap", "satan", "smurf", "back", "portsweep"]
    rows: list[tuple[str, ...]] = []

    for family in families:
        subset = frame.filter(pl.col("label") == family)
        if subset.height == 0:
            continue
        cells: list[str] = [family, str(subset.height)]
        for feature in FEATURES:
            stats = subset.select(
                pl.col(feature).mean().alias("mean"),
                pl.col(feature).min().alias("min"),
                pl.col(feature).max().alias("max"),
            ).row(0, named=True)
            cells.append(f"{stats['mean']:.1f}")
            cells.append(f"{stats['min']:.0f}-{stats['max']:.0f}")
        rows.append(tuple(cells))

    header = ["familia", "n"] + list(FEATURES) * 2
    out = [" | ".join(f"{h:>14}" for h in header)]
    out.append("-" * len(out[0]))
    out.extend(" | ".join(f"{c:>14}" for c in row) for row in rows)

    report = "\n".join(out)
    Path("output").mkdir(exist_ok=True)
    Path("output/kdd_profiles.txt").write_text(report, encoding="utf-8")
    # La consola de Windows no siempre es utf-8; el archivo ya quedo guardado.
    print(report.encode("ascii", "replace").decode("ascii"))  # noqa: T201


if __name__ == "__main__":
    main()
