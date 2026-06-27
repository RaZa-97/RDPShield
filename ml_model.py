"""
RDPShield - Threat-Score Inference  (runs ON THE SERVER, pure Python)
=====================================================================
Loads the JSON model produced by train_model.py and scores attacker IPs with a
0-100 "threat score". Uses ONLY the standard library, so it runs on the 32-bit
server with no scikit-learn / numpy.

A Random Forest prediction is just: drop the feature vector down every decision
tree, read the P(malicious) stored at the leaf it lands in, and average across
all trees. That average probability * 100 is the threat score.

Everything degrades gracefully: if ml_model.json is missing or unreadable
(e.g. the model has not been trained yet), model_available() is False and the
scorers return None / "untrained" instead of raising - so the dashboard keeps
working before the first model is ever trained.
"""

import os
import json
import time

from ml_features import (FEATURE_NAMES, features_to_row, compute_all_features)

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "ml_model.json")

# Score bands for colour-coding in the UI. (lower-bound inclusive)
BANDS = [
    (80, "critical"),
    (55, "high"),
    (30, "medium"),
    (0,  "low"),
]

# --- lazy-loaded model + short result cache --------------------------------
_model = None
_model_mtime = None
_scores_cache = None
_scores_cache_at = 0
_SCORES_TTL = 300            # seconds; dashboard hits this on every refresh


def _load_model():
    """Load ml_model.json once, reloading only if the file changed on disk."""
    global _model, _model_mtime
    try:
        mtime = os.path.getmtime(MODEL_PATH)
    except OSError:
        _model, _model_mtime = None, None
        return None
    if _model is None or mtime != _model_mtime:
        try:
            with open(MODEL_PATH, "r", encoding="utf-8") as fh:
                _model = json.load(fh)
            _model_mtime = mtime
        except (OSError, ValueError):
            _model, _model_mtime = None, None
    return _model


def model_available():
    return _load_model() is not None


def model_info():
    """Metadata for the dashboard header (trained_at, sample counts, AUC,
    feature importances) - or {'available': False} when untrained."""
    m = _load_model()
    if not m:
        return {"available": False}
    return {
        "available": True,
        "trained_at": m.get("trained_at"),
        "n_samples": m.get("n_samples"),
        "n_malicious": m.get("n_malicious"),
        "n_benign": m.get("n_benign"),
        "roc_auc": (m.get("metrics") or {}).get("roc_auc"),
        "n_trees": len(m.get("trees", [])),
        "feature_importance": m.get("feature_importance", {}),
    }


def _band(score):
    for lo, name in BANDS:
        if score >= lo:
            return name
    return "low"


def _walk_tree(nodes, row):
    """Follow one tree from the root to a leaf; return its P(malicious)."""
    i = 0
    # A leaf has no children (sklearn marks both child ids as -1).
    while nodes[i]["l"] != -1:
        node = nodes[i]
        if row[node["f"]] <= node["t"]:
            i = node["l"]
        else:
            i = node["r"]
    return nodes[i]["p"]


def score_row(row):
    """Threat score (0-100) for one ordered feature list, or None if untrained.
    Re-orders defensively if the model was trained on a different feature
    order than this code's FEATURE_NAMES (forward-compatibility)."""
    m = _load_model()
    if not m:
        return None
    trees = m["trees"]
    if not trees:
        return None
    p = sum(_walk_tree(t, row) for t in trees) / len(trees)
    return round(p * 100.0, 1)


def score_features(feat):
    """Threat score for a feature DICT (re-orders to the model's training order
    if it differs from the local FEATURE_NAMES)."""
    m = _load_model()
    if not m:
        return None
    names = m.get("feature_names", FEATURE_NAMES)
    row = [float(feat.get(name, 0.0)) for name in names]
    return score_row(row)


def score_ip(ip, conn=None):
    """Convenience: compute features for a single IP and score it. Returns a
    dict {ip, score, band} or None. (For one-off lookups; the dashboard uses
    score_active_ips() which is far cheaper in bulk.)"""
    feats = compute_all_features(conn)
    if ip not in feats:
        return None
    s = score_features(feats[ip])
    if s is None:
        return None
    return {"ip": ip, "score": s, "band": _band(s), "features": feats[ip]}


def score_active_ips(limit=200, use_cache=True):
    """Score every attacker IP and return the riskiest `limit`, newest model.

    Returns a list of dicts: {ip, score, band, <each feature>...} sorted by
    score descending. Cached for _SCORES_TTL seconds so the auto-refreshing
    dashboard does not recompute features on every poll. Returns [] if the
    model is untrained."""
    global _scores_cache, _scores_cache_at
    if not model_available():
        return []
    now = time.time()
    if use_cache and _scores_cache is not None and (now - _scores_cache_at) < _SCORES_TTL:
        return _scores_cache[:limit]

    feats = compute_all_features()
    rows = []
    for ip, f in feats.items():
        s = score_features(f)
        if s is None:
            continue
        row = {"ip": ip, "score": s, "band": _band(s)}
        row.update({k: round(v, 3) for k, v in f.items()})
        rows.append(row)
    rows.sort(key=lambda r: r["score"], reverse=True)

    _scores_cache = rows
    _scores_cache_at = now
    return rows[:limit]


def invalidate_cache():
    """Drop the cached scores (call after retraining / new data)."""
    global _scores_cache, _scores_cache_at
    _scores_cache, _scores_cache_at = None, 0


if __name__ == "__main__":
    # Quick manual check: print the top 20 riskiest IPs from the local DB.
    info = model_info()
    if not info["available"]:
        print("[ML] No trained model found (ml_model.json). Run train_model.py first.")
    else:
        print(f"[ML] Model trained {info['trained_at']} on {info['n_samples']} IPs, "
              f"ROC-AUC={info['roc_auc']}")
        print(f"{'IP':<18}{'SCORE':>7}  BAND")
        for r in score_active_ips(limit=20, use_cache=False):
            print(f"{r['ip']:<18}{r['score']:>7}  {r['band']}")
