import csv
import pickle
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score

ROOT=Path(__file__).resolve().parents[1]
DATASET=ROOT / "data" / "ml_training_seed.csv"
MODEL_OUT= ROOT / "data" / "ml_model.pkl"
FEATURE_ORDER = [
    "is_create",
    "is_modify",
    "is_delete",
    "is_rename",
    "source_watcher",
    "source_wp_sensor",
    "has_actor",
    "has_old_path",
    "burst_count_norm",
    "path_depth_norm",
    "is_php",
    "is_zip",
    "is_sensitive_file",
    "is_sensitive_dir",
    "is_media_upload",
    "is_plugin_dir",
    "is_theme_dir",
    "is_core_dir",
]

def loadDataset():
    x_rows =[]
    y_rows=[]

    with open(DATASET, "r",encoding="utf-8",newline="") as h:
        reader= csv.DictReader(h)

        for row in reader:
            x_rows.append([float(row[name]) for name in FEATURE_ORDER])
            y_rows.append(row["label"].strip().lower())

    
    return x_rows,y_rows


def main():

    if not DATASET.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET}")
    
    x_rows,y_rows =loadDataset()

    model=GradientBoostingClassifier(
        random_state=42,
        n_estimators=120,
        learning_rate=0.08,
        max_depth=3,
    )
    #Train the local scoring model.
    model.fit(x_rows,y_rows)
    predictions=model.predict(x_rows)
    train_accuracy = accuracy_score(y_rows,predictions)

    bundle ={
        "version": "model-seed-v1",
        "feature_order": FEATURE_ORDER,
        "class_names": list(model.classes_),
        "train_size":len(y_rows),
        "train_accuracy":float(train_accuracy),
        "model":model,
    }

    MODEL_OUT.parent.mkdir(parents=True,exist_ok=True)
    
    with open(MODEL_OUT,"wb") as h:
        pickle.dump(bundle,h)

    print(f"Saved model to {MODEL_OUT}")
    print(f"Train size:{len(y_rows)}")
    print(f"Train accuracy: {train_accuracy:.4f}")


if __name__ == "__main__":
    main()