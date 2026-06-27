"""
RDPShield - Threat-Score Model Trainer  (run OFFLINE, on a 64-bit machine)
==========================================================================
Reads the collected attack data from rdpshield.db, trains a Random Forest to
predict whether an IP is malicious, prints an evaluation, and EXPORTS the
trained model to a plain-JSON file (ml_model.json) that the server scores with
- no scikit-learn required on the server.

WHY THIS SPLIT
--------------
The live server runs 32-bit Python 3.11, where scikit-learn / numpy wheels are
painful (the same class of problem psutil 7.x caused). So we keep the heavy
training here, on a normal 64-bit Python, and ship only a small JSON file. The
server's ml_model.py walks that JSON with pure Python. Training and scoring
share ml_features.py, so the feature definitions can never drift apart.

WHY A RANDOM FOREST
-------------------
- Handles non-linear thresholds (exactly what our rule engine is) and feature
  interactions without any feature scaling.
- Gives feature importances for free - great for the dissertation write-up.
- A forest is just a set of if/else decision trees, so it exports to JSON and
  re-implements in ~20 lines of pure Python (see ml_model.py).

USAGE
-----
    pip install scikit-learn          # 64-bit training box only, NOT the server
    python train_model.py             # uses ./rdpshield.db
    python train_model.py path\to\rdpshield.db

Then commit ml_model.json and `git pull` it onto the server. No restart needed
beyond the usual - ml_model.py picks the new file up on its next load.
"""

import sys
import json
from datetime import datetime

# scikit-learn / numpy are imported lazily inside main() so that importing this
# module never breaks an environment that lacks them (e.g. the 32-bit server).


MODEL_PATH = "ml_model.json"
MODEL_SCHEMA_VERSION = 1


def _export_tree(tree):
    """Convert one sklearn DecisionTree into JSON-friendly arrays.

    A sklearn tree is stored as parallel arrays indexed by node id:
      children_left[i] / children_right[i]  child node ids (-1 at a leaf)
      feature[i]                            feature index tested at node i
      threshold[i]                          go left if x[feature] <= threshold
      value[i]                              class counts [neg, pos] at node i
    We keep exactly those, plus a per-node P(malicious) so scoring is a plain
    tree walk with no math.
    """
    t = tree.tree_
    nodes = []
    for i in range(t.node_count):
        counts = t.value[i][0]                     # [neg_count, pos_count]
        total = float(counts.sum()) or 1.0
        p_pos = float(counts[1] / total) if len(counts) > 1 else 0.0
        nodes.append({
            "l": int(t.children_left[i]),
            "r": int(t.children_right[i]),
            "f": int(t.feature[i]),
            "t": float(t.threshold[i]),
            "p": round(p_pos, 6),
        })
    return nodes


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else None

    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import (roc_auc_score, classification_report,
                                      confusion_matrix)
    except ImportError:
        print("[ML] scikit-learn / numpy are required to TRAIN.")
        print("[ML]   pip install scikit-learn")
        print("[ML] (The server does NOT need them - it scores from ml_model.json.)")
        sys.exit(1)

    # Point database.py at the chosen DB before importing the feature builder.
    if db_path:
        import config
        config.DATABASE_PATH = db_path

    from ml_features import build_training_matrix, FEATURE_NAMES

    print("[ML] Building feature matrix from the database...")
    ips, X, y = build_training_matrix()
    n = len(y)
    n_pos = sum(y)
    n_neg = n - n_pos
    print(f"[ML] {n} IPs total  |  malicious(1)={n_pos}  benign(0)={n_neg}")

    if n < 20:
        print("[ML] Not enough data to train a meaningful model yet "
              "(need ~20+ IPs). Let the honeypot collect more, then re-run.")
        sys.exit(1)
    if n_pos == 0 or n_neg == 0:
        print("[ML] Only one class present - a classifier needs BOTH malicious "
              "and benign IPs. Collect more data (or revisit the label).")
        sys.exit(1)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    # Stratified split keeps the same malicious:benign ratio in train and test.
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=8,              # shallow => generalises + small JSON
        min_samples_leaf=2,
        class_weight="balanced",  # honeypots are class-imbalanced
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_tr, y_tr)

    # --- Evaluation -------------------------------------------------------
    proba_te = clf.predict_proba(X_te)[:, 1]
    pred_te = (proba_te >= 0.5).astype(int)
    print("\n========== EVALUATION (held-out 25% test set) ==========")
    auc_value = None
    try:
        auc_value = float(roc_auc_score(y_te, proba_te))
        print(f"ROC-AUC : {auc_value:.3f}   (1.0 = perfect, 0.5 = coin flip)")
    except ValueError:
        print("ROC-AUC : n/a (test fold has a single class)")
    print("\nConfusion matrix [rows=actual, cols=predicted]:")
    print("            pred_benign  pred_malicious")
    cm = confusion_matrix(y_te, pred_te, labels=[0, 1])
    print(f"  benign       {cm[0][0]:>6}        {cm[0][1]:>6}")
    print(f"  malicious    {cm[1][0]:>6}        {cm[1][1]:>6}")
    print("\nClassification report:")
    print(classification_report(y_te, pred_te,
                                target_names=["benign", "malicious"],
                                zero_division=0))

    # --- Feature importances (the dissertation gold) ----------------------
    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_),
                         key=lambda kv: kv[1], reverse=True)
    print("========== FEATURE IMPORTANCE (what drives the score) ==========")
    for name, imp in importances:
        bar = "#" * int(round(imp * 50))
        print(f"  {name:<20} {imp:6.3f}  {bar}")

    # --- Export to portable JSON -----------------------------------------
    model = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "model_type": "random_forest_classifier",
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "feature_names": FEATURE_NAMES,
        "n_samples": int(n),
        "n_malicious": int(n_pos),
        "n_benign": int(n_neg),
        "metrics": {
            "roc_auc": auc_value,
        },
        "feature_importance": {name: round(float(imp), 6)
                               for name, imp in importances},
        "trees": [_export_tree(est) for est in clf.estimators_],
    }
    with open(MODEL_PATH, "w", encoding="utf-8") as fh:
        json.dump(model, fh)
    size_kb = round(len(json.dumps(model)) / 1024, 1)
    print(f"\n[ML] Exported {len(model['trees'])}-tree model -> {MODEL_PATH} "
          f"({size_kb} KB)")
    print("[ML] Commit ml_model.json and git pull it onto the server.")


if __name__ == "__main__":
    main()
