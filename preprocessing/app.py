from __future__ import annotations

from pathlib import Path
import json

from flask import Blueprint, Flask, render_template

ROOT = Path(__file__).resolve().parent

SUMMARY_FILES = [
    ROOT / "malware_summary.json",
    ROOT / "dataset_test_summary.json",
    ROOT / "cicids_summary.json",
    ROOT / "nslkdd_summary.json",
    ROOT / "unsw_summary.json",
]

main = Blueprint("main", __name__)


def _load_summary(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@main.route("/", methods=["GET"])
def index() -> str:
    results: list[dict[str, object]] = []
    for path in SUMMARY_FILES:
        summary = _load_summary(path)
        if summary is None:
            results.append(
                {
                    "dataset_name": path.stem.replace("_summary", "").upper(),
                    "status": "Missing",
                    "summary": None,
                }
            )
        else:
            results.append(
                {
                    "dataset_name": summary.get("dataset_name", path.stem),
                    "status": summary.get("preprocessing_status", "Completed"),
                    "summary": summary,
                }
            )

    return render_template("index.html", results=results)


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(main)
    return app


if __name__ == "__main__":
    create_app().run(debug=True)
