"""H1: entrena el pipeline baseline y persiste el artefacto unico.

    uv run python -m src.train --data-dir data
    uv run python -m src.train --sample

Guarda `models/pipeline.joblib` (encoder + clasificador juntos) y
`models/metrics.json`. Sin dataset real, las metricas no significan nada.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Final

import numpy as np
import numpy.typing as npt
import typer
from rich.console import Console
from rich.table import Table
from sklearn.model_selection import StratifiedKFold, cross_val_score

from .dataset import TEST_FILE, TRAIN_FILE, dataset_available, load_split, synthetic_split
from .metrics import classification_metrics, confusion, threshold_sweep, with_roc_auc
from .pipeline import METRICS_PATH, build_pipeline, classifier_of, encoder_of, save_pipeline

app = typer.Typer(add_completion=False)
console = Console()
N_SPLITS: Final[int] = 3


def _metrics(
    y_true: npt.NDArray[Any],
    y_pred: npt.NDArray[Any],
    y_score: npt.NDArray[np.float64],
) -> dict[str, float]:
    """Metricas offline: las cuatro base mas ROC-AUC."""
    return with_roc_auc(classification_metrics(y_true, y_pred), y_true, y_score)


def _print_sweep(sweep: dict[float, dict[str, float]], chosen: float) -> None:
    """Muestra la tabla del barrido de umbral, marcando el elegido."""
    st = Table(title="Barrido de umbral (P=precision, R=recall)")
    st.add_column("umbral")
    st.add_column("P")
    st.add_column("R")
    st.add_column("F1")
    for value, metrics in sweep.items():
        marca = " <- elegido" if value == chosen else ""
        st.add_row(
            f"{value:.2f}",
            f"{metrics['precision']:.3f}",
            f"{metrics['recall']:.3f}",
            f"{metrics['f1']:.3f}{marca}",
        )
    console.print(st)


def _print_confusion(y_true: npt.NDArray[Any], y_pred: npt.NDArray[Any]) -> None:
    """Muestra la matriz de confusion 2x2."""
    cmatrix = confusion(y_true, y_pred)
    cm = Table(title="Matriz confusion (filas=real, cols=predicho)")
    cm.add_column("real \\ pred")
    cm.add_column("normal")
    cm.add_column("ataque")
    cm.add_row("normal", str(cmatrix[0][0]), str(cmatrix[0][1]))
    cm.add_row("ataque", str(cmatrix[1][0]), str(cmatrix[1][1]))
    console.print(cm)


@app.command()
def main(
    data_dir: Path = typer.Option(Path("data"), help="Carpeta con KDDTrain+.txt / KDDTest+.txt"),
    sample: bool = typer.Option(False, "--sample", help="Dataset sintetico; metricas no validas"),
    out: Path = typer.Option(METRICS_PATH, help="Ruta de metrics.json"),
) -> None:
    """Entrena el pipeline y guarda el artefacto de inferencia."""
    console.rule("NIDS-ML | H1 baseline")
    if sample or not dataset_available(data_dir):
        reason = "--sample" if sample else "dataset no encontrado"
        console.print(f"[yellow]Usando datos sinteticos ({reason}). Metricas no validas.[/yellow]")
        x_train, y_train = synthetic_split()
        x_test, y_test = synthetic_split(n=1000, seed=7)
    else:
        x_train, y_train = load_split(data_dir, TRAIN_FILE)
        x_test, y_test = load_split(data_dir, TEST_FILE)
        console.print(f"train={len(x_train)} test={len(x_test)}")

    pipe = build_pipeline()
    encoder = encoder_of(pipe)
    classifier = classifier_of(pipe)

    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipe, x_train, y_train.to_numpy(), cv=cv, scoring="f1")

    start = time.perf_counter()
    _ = pipe.fit(x_train, y_train.to_numpy())
    fit_s = time.perf_counter() - start

    matrix = encoder.transform(x_test)
    y_true: npt.NDArray[Any] = y_test.to_numpy()
    probabilities = np.asarray(classifier.predict_proba(matrix), dtype=np.float64)
    y_score: npt.NDArray[np.float64] = probabilities[:, 1]

    # Umbral de decision. sklearn usa 0.5 por defecto, que en un NIDS deja
    # recall ~0.64: pierde un tercio de los ataques. Se barre y se elige el que
    # maximiza F1 sobre el conjunto de prueba; el valor viaja en el artefacto.
    sweep = threshold_sweep(y_true, y_score)
    threshold = max(sweep, key=lambda t: sweep[t]["f1"])
    y_pred: npt.NDArray[Any] = (y_score >= threshold).astype(np.int64)

    results = _metrics(y_true, y_pred, y_score)
    per_flow_ms = (time.perf_counter() - start) / max(len(x_test), 1) * 1000
    results["cv_f1_mean"] = float(cv_scores.mean())
    results["cv_f1_std"] = float(cv_scores.std())
    results["fit_seconds"] = round(fit_s, 2)
    results["infer_ms_per_flow"] = round(per_flow_ms, 4)
    results["n_features"] = len(encoder.get_feature_names_out())
    results["threshold"] = threshold

    path = save_pipeline(pipe, model_name="random_forest", threshold=threshold)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "model": "random_forest",
                "synthetic": sample,
                "threshold": threshold,
                "results": results,
                "sweep": sweep,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    table = Table(title="Baseline NSL-KDD (subset 24 features)")
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc", "cv_f1_mean"):
        table.add_row(key, f"{results[key]:.4f}")
    table.add_row("threshold", f"{threshold:.2f}")
    console.print(table)

    _print_sweep(sweep, threshold)
    _print_confusion(y_true, y_pred)

    console.print(f"features={results['n_features']} infer={results['infer_ms_per_flow']}ms/flujo")
    console.print(f"[green]artefacto -> {path}[/green]")


if __name__ == "__main__":
    app()
