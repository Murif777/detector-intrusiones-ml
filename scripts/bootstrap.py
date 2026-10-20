"""Prepara el proyecto desde cero: descarga el dataset, entrena y verifica.

    uv run python scripts/bootstrap.py
    uv run python scripts/bootstrap.py --force
    uv run python scripts/bootstrap.py --train-only

Lo corren por igual un companero que clona el repo y la CI que construye la
imagen. Al terminar deja `models/pipeline.joblib` listo y comprueba que el
sistema responde.

Es idempotente: si el dataset ya esta, no lo vuelve a bajar; si el artefacto ya
existe, lo reporta sin reentrenar (usa `--force` para forzar). Con `--train-only`
se detiene tras el entrenamiento, sin correr la verificacion: lo usa el build de
Docker, que no tiene red ni interfaz para la demo.
"""

from __future__ import annotations

import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Final

from rich.console import Console

console = Console()

DATA_DIR: Final[Path] = Path("data")
MODELS_DIR: Final[Path] = Path("models")
PIPELINE: Final[Path] = MODELS_DIR / "pipeline.joblib"

#: Espejo publico de NSL-KDD. El dataset es de terceros: no se versiona, se baja.
BASE_URL: Final[str] = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master"
DATASETS: Final[tuple[tuple[str, str], ...]] = (
    ("KDDTrain+.txt", "KDDTrain%2B.txt"),
    ("KDDTest+.txt", "KDDTest%2B.txt"),
)


def download(name: str, remote: str) -> Path:
    """Descarga un archivo del dataset si no esta. Devuelve su ruta."""
    target = DATA_DIR / name
    if target.exists() and target.stat().st_size > 0:
        console.print(f"  [dim]{name} ya esta ({target.stat().st_size / 1e6:.1f} MB)[/dim]")
        return target

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    url = f"{BASE_URL}/{remote}"
    console.print(f"  bajando {name}...")
    try:
        urllib.request.urlretrieve(url, target)  # noqa: S310 - URL fija y conocida
    except (urllib.error.URLError, OSError) as exc:
        console.print(f"[red]No se pudo bajar {name}: {exc}[/red]")
        console.print(f"[dim]Bajalo a mano desde {url}[/dim]")
        raise SystemExit(1) from exc
    console.print(f"  [green]{name} listo ({target.stat().st_size / 1e6:.1f} MB)[/green]")
    return target


def fetch_dataset() -> None:
    """Descarga ambos archivos de NSL-KDD."""
    console.rule("[bold]1/3 Dataset")
    for name, remote in DATASETS:
        download(name, remote)


def train(force: bool) -> None:
    """Entrena el modelo si hace falta."""
    console.rule("[bold]2/3 Entrenamiento")
    if PIPELINE.exists() and not force:
        console.print(f"  [dim]{PIPELINE} ya existe - se omite (usa --force para reentrenar)[/dim]")
        return
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "src.train", "--data-dir", str(DATA_DIR)],
        check=False,
    )
    if result.returncode != 0:
        console.print("[red]El entrenamiento fallo.[/red]")
        raise SystemExit(result.returncode)


def verify() -> None:
    """Corre la demo para comprobar que el sistema responde."""
    console.rule("[bold]3/3 Verificacion")
    result = subprocess.run(
        [sys.executable, "scripts/demo.py"],
        check=False,
    )
    if result.returncode != 0:
        console.print("[red]La verificacion fallo: revisa la salida de arriba.[/red]")
        raise SystemExit(result.returncode)


def main() -> int:
    """Ejecuta las etapas. Devuelve 0 si todo sale bien.

    `--force` reentrena aunque el artefacto ya exista. `--train-only` se detiene
    tras el entrenamiento (lo usa el build de Docker, que no puede verificar la
    demo: no hay red ni una interfaz para capturar).
    """
    force = "--force" in sys.argv
    train_only = "--train-only" in sys.argv
    console.rule("[bold]NIDS-ML - preparacion completa[/bold]")
    fetch_dataset()
    train(force)
    if not train_only:
        verify()
    console.print("\n[bold green]Listo.[/bold green]")
    console.print("  Demo en vivo:  [cyan]docker compose up --build[/cyan]")
    console.print("  Dashboard:     [cyan]uv run streamlit run dashboard.py[/cyan]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
