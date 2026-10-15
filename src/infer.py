"""H1b: scoring batch sobre un CSV de flujos, sin PCAP.

    uv run python -m src.infer --csv data/captura_ISCX.csv
    uv run python -m src.infer --csv flujos.csv --report output/infer.json

Util para datasets que ya viene en formato de flujo (CICFlowMeter, UNSW-NB15)
y para medir el salto cross-dataset sin volver a capturar trafico.

Si el CSV trae columna de etiqueta, calcula metricas contra la verdad. Ese es
el numero que mas duele en el informe: un modelo entrenado en NSL-KDD que se
desmorona sobre otro dataset es un hallazgo, no un fallo del codigo.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import numpy.typing as npt
import polars as pl
import typer
from rich.console import Console
from rich.table import Table

from .alerts import ALERTS_PATH, append_alert, make_alert
from .dataset import load_flows_csv
from .metrics import classification_metrics, confusion, predictions_to_array
from .pipeline import PIPELINE_PATH, ModelBundle, load_pipeline, predict_flow
from .schema import FlowFeatures, Prediction

app = typer.Typer(add_completion=False)
console = Console()


def score_flows(flows: list[FlowFeatures], bundle: ModelBundle) -> list[Prediction]:
    """Clasifica una lista de flujos con el encoder del artefacto.

    `pipe` es el `Pipeline` serializado: al llamar a `predict_flow` se usa su
    `FlowEncoder` interno, no una copia. Por eso este camino no puede divergir
    del entrenamiento; es el mismo invariante que protege `src/replay.py`.
    """
    return [predict_flow(bundle, flow) for flow in flows]


def evaluate(y_true: npt.NDArray[np.int64], predictions: list[Prediction]) -> dict[str, float]:
    """Metricas de clasificacion binaria contra la verdad del CSV."""
    return classification_metrics(y_true, predictions_to_array(predictions))


def _print_summary(count: int, attacks: int, elapsed_ms: float) -> None:
    """Muestra la tabla de volumetria del lote."""
    table = Table(title="Resumen batch")
    table.add_row("flujos", str(count))
    table.add_row("predichos ataque", str(attacks))
    table.add_row("ratio ataque", f"{attacks / max(count, 1):.4f}")
    table.add_row("ms/flujo", f"{elapsed_ms / max(count, 1):.4f}")
    console.print(table)


def _print_ground_truth(
    y_true: npt.NDArray[np.int64], predictions: list[Prediction]
) -> dict[str, float]:
    """Compara contra la etiqueta real del CSV. Devuelve las metricas."""
    metrics = evaluate(y_true, predictions)

    mtable = Table(title="Metricas contra la verdad del CSV")
    for key, value in metrics.items():
        mtable.add_row(key, f"{value:.4f}")
    console.print(mtable)

    cm = confusion(y_true, predictions_to_array(predictions))
    ctable = Table(title="Matriz confusion")
    ctable.add_column("real \\ pred")
    ctable.add_column("normal")
    ctable.add_column("ataque")
    ctable.add_row("normal", str(cm[0][0]), str(cm[0][1]))
    ctable.add_row("ataque", str(cm[1][0]), str(cm[1][1]))
    console.print(ctable)

    caveat = (
        "[yellow]Comparar entre datasets distintos se llama generalization gap, "
        'no "accuracy".[/yellow]'
    )
    console.print(caveat)
    return metrics


def _persist_attacks(flows: list[FlowFeatures], predictions: list[Prediction]) -> None:
    """Anade solo los predichos como ataque al store de alertas."""
    for flow, prediction in zip(flows, predictions, strict=True):
        if prediction.is_attack:
            append_alert(make_alert(prediction, flow))
    console.print(f"ataques agregados a {ALERTS_PATH}")


@app.command()
def main(
    csv_path: Path = typer.Option(..., "--csv", help="CSV de flujos con cabecera"),
    report: Path | None = typer.Option(None, "--report", help="Donde escribir el JSON"),
    persist: bool = typer.Option(False, "--persist", help="Anadir ataques a alertas.jsonl"),
    limit: int = typer.Option(0, "--limit", help="Maximo de filas a puntuar (0=todas)"),
) -> None:
    """Puntua un CSV de flujos y, si trae etiqueta, mide el desempeÃƒÂ±o."""
    console.rule("NIDS-ML | H1b infer batch")
    if not csv_path.exists():
        msg = f"CSV no encontrado: {csv_path}"
        raise typer.BadParameter(msg)

    bundle = load_pipeline()
    if bundle is None:
        msg = "Modelo no entrenado. Ejecuta primero: uv run python -m src.train --data-dir data"
        raise typer.BadParameter(msg)

    flows, labels = load_flows_csv(csv_path)
    if limit > 0:
        flows = flows[:limit]
        if labels is not None:
            labels = pl.Series(labels[:limit].to_list())
    console.print(
        f"flujos={len(flows)} etiquetado={labels is not None} modelo={bundle.model_name}"
    )

    start = time.perf_counter()
    predictions = score_flows(flows, bundle)
    elapsed_ms = (time.perf_counter() - start) * 1000
    attacks = sum(1 for p in predictions if p.is_attack)

    if persist:
        _persist_attacks(flows, predictions)

    _print_summary(len(flows), attacks, elapsed_ms)

    payload: dict[str, object] = {
        "csv": str(csv_path),
        "model": bundle.model_name,
        "n_flows": len(flows),
        "predicted_attacks": attacks,
        "ms_per_flow": round(elapsed_ms / max(len(flows), 1), 4),
        "artefact": str(PIPELINE_PATH),
    }

    if labels is not None:
        payload["metrics"] = _print_ground_truth(labels.to_numpy().astype(np.int64), predictions)

    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]reporte -> {report}[/green]")


if __name__ == "__main__":
    app()
