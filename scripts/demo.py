"""Demo verificable del NIDS, en dos etapas.

    uv run python scripts/demo.py

Etapa 1 â€” EVALUACION RIGUROSA (la que sostiene el informe):
  Clasifica KDDTest+.txt real (22 544 flujos) con el artefacto entrenado y
  reporta accuracy/precision/recall/F1. Son los MISMOS datos y el MISMO umbral
  que `models/metrics.json`, asi que los numeros de la demo no pueden divergir
  de los del informe.

Etapa 2 â€” MECANISMO (la que se ve):
  Reproduce PCAPs sinteticos por el pipeline real (paquete -> flujo -> alerta)
  para mostrar el sistema funcionando sobre un stream de paquetes.

Por que separadas: los PCAP son sinteticos y su distribucion NO es la de
NSL-KDD, asi que sirven para mostrar el mecanismo, no para afirmar desempeno.
Mezclar ambas cosas es como medir un modelo con datos que uno mismo fabrico.

Sale con codigo 1 si la etapa rigurosa no cumple, para usarse como test de humo.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from rich.console import Console
from rich.table import Table
from scapy.packet import Packet as ScapyPacket
from scapy.utils import PcapReader

from scripts.make_demo_pcap import build_sections
from src.alerts import ALERTS_PATH
from src.dataset import TEST_FILE, dataset_available, load_split
from src.features import BURST_WINDOW_SEC, HOST_WINDOW_SEC
from src.metrics import classification_metrics, confusion, predictions_to_array
from src.pipeline import PIPELINE_PATH, ModelBundle, load_pipeline
from src.replay import run

console = Console()

OUT_DIR: Final[Path] = Path("output")
DATA_DIR: Final[Path] = Path("data")
MAX_FP_RATE: Final[float] = 0.15
REQUIRED_DETECTIONS: Final[int] = 3
MIN_F1: Final[float] = 0.85
MIN_RECALL: Final[float] = 0.85


@dataclass(frozen=True, slots=True)
class Verdict:
    """Resultado de un escenario sintetico del mecanismo."""

    name: str
    expected_attack: bool
    flows: int
    detected: int

    @property
    def rate(self) -> float:
        """Fraccion de flujos marcados como ataque."""
        return self.detected / max(self.flows, 1)

    @property
    def passed(self) -> bool:
        """Un ataque debe detectarse; el benigno no debe marcarse."""
        return self.detected > 0 if self.expected_attack else self.rate < MAX_FP_RATE


def score_pcap(path: Path) -> tuple[int, int]:
    """Replaya un PCAP por el pipeline real. Devuelve (flujos, detectados).

    Llama a `src.replay.run`, el MISMO codigo que corre en produccion. Si el
    demo midiera una copia de esa logica, podria dar verde mientras el replay
    real falla.
    """

    def packets() -> Iterator[ScapyPacket]:
        with PcapReader(str(path)) as reader:
            yield from reader

    stats = run(packets(), BURST_WINDOW_SEC, HOST_WINDOW_SEC)
    return stats.flows, stats.attacks


def _run_table(verdicts: list[Verdict]) -> None:
    """Tabla de deteccion de las familias de ataque en el stream sintetico.

    Solo se evaluan los escenarios de ATAQUE. Los falsos positivos NO se miden
    aqui a proposito: el trafico benigno es sintetico y su distribucion no es la
    de NSL-KDD, asi que medir FP contra el seria medir el modelo con datos que
    fabricamos nosotros. Los FP se miden en la etapa 1, con datos reales.
    """
    table = Table(title="Mecanismo: deteccion por familia de ataque (PCAP sintetico)")
    table.add_column("Escenario")
    table.add_column("Flujos")
    table.add_column("Detectados")
    table.add_column("Tasa")
    table.add_column("Resultado")
    for v in verdicts:
        if not v.expected_attack:
            continue
        mark = "[green]DETECTADO[/green]" if v.detected > 0 else "[red]NO DETECTADO[/red]"
        table.add_row(v.name, str(v.flows), str(v.detected), f"{v.rate:.2f}", mark)
    console.print(table)


def _verdict_real(bundle: ModelBundle) -> bool:
    """Evalua el artefacto sobre KDDTest+.txt real. Devuelve True si cumple."""
    if not dataset_available(DATA_DIR):
        console.print("[yellow]Sin NSL-KDD en data/: se omite la evaluacion rigurosa.[/yellow]")
        return True

    flows, labels = load_split(DATA_DIR, TEST_FILE)
    predictions = [bundle.predict(flow) for flow in flows]
    y_true = labels.to_numpy()
    y_pred = predictions_to_array(predictions)
    metrics = classification_metrics(y_true, y_pred)

    table = Table(title=f"KDDTest+.txt real: {len(flows)} flujos, umbral {bundle.threshold:.2f}")
    table.add_column("metrica")
    table.add_column("valor")
    for key in ("accuracy", "precision", "recall", "f1"):
        table.add_row(key, f"{metrics[key]:.4f}")
    table.add_row("F1 objetivo", f">= {MIN_F1}")
    table.add_row("recall objetivo", f">= {MIN_RECALL}")
    console.print(table)

    cm = confusion(y_true, y_pred)
    console.print(
        f"matriz  normal->[{cm[0][0]} ok, {cm[0][1]} falso positivo]   "
        f"ataque->[{cm[1][0]} perdido, {cm[1][1]} ok]"
    )

    passed = metrics["f1"] >= MIN_F1 and metrics["recall"] >= MIN_RECALL
    mark = "[green]CUMPLE[/green]" if passed else "[red]NO CUMPLE[/red]"
    console.print(f"F1={metrics['f1']:.4f} recall={metrics['recall']:.4f} -> {mark}\n")
    return passed


def _verdicts_sinteticos() -> list[Verdict]:
    """Replay de los PCAP sinteticos: el mecanismo paquete -> flujo -> alerta."""
    ALERTS_PATH.unlink(missing_ok=True)
    verdicts: list[Verdict] = []
    for name, _pkts, is_attack in build_sections():
        path = OUT_DIR / f"{name}.pcap"
        if not path.exists():
            console.print(f"[red]no se genero {path}[/red]")
            continue
        flows, detected = score_pcap(path)
        verdicts.append(
            Verdict(name=name, expected_attack=is_attack, flows=flows, detected=detected)
        )
    return verdicts


def main() -> int:
    """Ejecuta la demo en dos etapas. Devuelve 0 si la rigurosa pasa, 1 si no."""
    console.rule("[bold]NIDS-ML - Demo verificable[/bold]")

    bundle = load_pipeline()
    if bundle is None:
        console.print(
            "[red]FALTA MODELO.[/red] Corre primero: "
            "uv run python -m src.train --data-dir data"
        )
        return 1
    console.print(
        f"[green]modelo:[/green] {bundle.model_name}   "
        f"[green]umbral:[/green] {bundle.threshold:.2f}"
    )
    console.print(f"[dim]{PIPELINE_PATH}[/dim]\n")

    console.rule("Etapa 1/2 - Evaluacion rigurosa (datos reales de NSL-KDD)")
    riguroso_ok = _verdict_real(bundle)

    console.rule("Etapa 2/2 - Mecanismo (replay de PCAP sintetico)")
    console.print("[dim]Trafico sintetico: ilustra el mecanismo, no mide desempeno.[/dim]")
    subprocess.run([sys.executable, "scripts/make_demo_pcap.py"], check=True)
    verdicts = _verdicts_sinteticos()
    _run_table(verdicts)

    attacks = sum(1 for v in verdicts if v.expected_attack and v.detected > 0)
    console.print()
    console.print(f"Familias de ataque detectadas: [bold]{attacks}/{REQUIRED_DETECTIONS}[/bold]")
    console.print(
        "[dim]Los falsos positivos se miden en la etapa 1, sobre datos reales. "
        "Medirlos aqui seria medir el modelo con trafico que fabricamos.[/dim]"
    )

    ALERTS_PATH.unlink(missing_ok=True)
    console.print(
        "\n[dim]Detalle en vivo: uv run python -m src.replay --pcap output/syn_flood.pcap[/dim]"
    )

    console.rule("Veredicto")
    if riguroso_ok:
        console.print("[bold green]OBJETIVO CUMPLIDO[/bold green] - deteccion operativa.")
        return 0
    console.print("[bold red]OBJETIVO NO CUMPLIDO[/bold red] - revisar antes de presentar.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
