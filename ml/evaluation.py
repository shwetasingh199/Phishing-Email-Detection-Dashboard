from pathlib import Path
import json

metrics_path = Path(__file__).resolve().parent.parent / "models" / "metrics.json"

if not metrics_path.exists():
    print("No metrics found. Run: python ml/train_model.py")
else:
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    print("Evaluation results:")
    for key, value in metrics.items():
        print(f"{key}: {value}")
