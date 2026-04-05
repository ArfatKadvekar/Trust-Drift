"""
severity_scorer.py
==================
Trust-Drift Severity Scorer — signal generator layer.

This module is completely independent of the Trust Engine.
It consumes scaled network flow data and produces structured severity signals.

Usage
-----
    from severity_scorer import SeverityScorer

    scorer = SeverityScorer(
        autoencoder=ae, encoder_model=enc, iso_forest=iso,
        scaler=scaler, feature_names=feature_cols
    )
    scorer.calibrate(X_train)                    # fit on benign-only data

    severity, diag = scorer.score_row(x)         # single-row API
    df_out = scorer.score_dataset(X, y, names)   # batch API

Interface contract
------------------
    Input  : x  np.ndarray (n_features,)     — single scaled network flow
    Output : severity_score  float ∈ [0, 1]  — passed to TrustDriftEngine
    Output : diagnostics     dict             — consumed by Explainability Module

Diagnostics dict format (exact spec):
    {
        "severity_score": float,
        "ae_score":       float,
        "if_score":       float,
        "weights": {
            "ae": float,
            "if": float,
        },
        "top_features":   list[str],     # top-N by |x - x_hat|
        "feature_errors": list[float],   # |x - x_hat| for ALL features
    }

No verdict text. No explanation text. Structured numbers only.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# SeverityScorer
# ─────────────────────────────────────────────────────────────────────────────

class SeverityScorer:
    """
    Hybrid AE + IF severity scorer.

    Responsibilities
    ----------------
    - Compute per-row AE reconstruction error and IF isolation score
    - Normalize both signals robustly using percentile anchors
    - Combine using dynamic per-row weights
    - Return structured diagnostics for the Explainability Module

    Design decisions
    ----------------

    ROBUST PERCENTILE NORMALIZATION (1st / 99th pct)
        Min/max normalization collapses all scores at or above the calibration
        max to exactly 1.0 — severe attacks are indistinguishable from mild ones.
        Percentile anchors are fitted to the bulk of benign behavior so a handful
        of atypical calibration flows cannot dominate the scale. Attack scores
        spread meaningfully in (0, 1] instead of spiking straight to the ceiling.

    DYNAMIC PER-ROW WEIGHTING
        w_ae(i) = ae_norm(i) / (ae_norm(i) + if_norm(i) + ε)
        w_if(i) = 1 − w_ae(i)
        combined(i) = w_ae(i) × ae_norm(i) + w_if(i) × if_norm(i)

        Gradual behavioral drift → AE fires more → AE weight dominates.
        Sudden structural outlier → IF fires more → IF weight dominates.
        Equal firing → 0.5 / 0.5 (reduces to plain average).
        When both are 0 (perfectly benign) → weights are 0.5/0.5 but
        combined is 0 regardless — no effect on Trust Engine.

    ABSOLUTE FEATURE ERROR  |x − x̂|
        Per spec. Linear ranking of feature deviations — more interpretable
        than squared error, which exaggerates large deviations and mutes small ones.
        The row-level AE signal still uses MSE (appropriately penalises severe rows).

    EMA SMOOTHING (score_dataset only)
        smoothed(t) = α × raw(t) + (1−α) × smoothed(t−1)
        Prevents a single noisy packet from spiking the Trust Engine.
        Configurable via ema_alpha. Set smooth=False to disable.

    Parameters
    ----------
    autoencoder   : keras Model  — trained AE (reconstructs normal traffic)
    encoder_model : keras Model  — encoder sub-model (for bottleneck features)
    iso_forest    : IsolationForest — trained IF
    scaler        : MinMaxScaler — fitted on Monday benign data
    feature_names : list[str]    — feature column names in order
    top_n         : int          — how many top features to return (default 5)
    norm_pct_low  : int          — lower percentile anchor (default 1)
    norm_pct_high : int          — upper percentile anchor (default 99)
    ema_alpha     : float        — EMA smoothing factor  0=none  1=no memory
    """

    def __init__(
        self,
        autoencoder,
        encoder_model,
        iso_forest,
        scaler,
        feature_names: list[str],
        top_n: int   = 5,
        norm_pct_low:  int   = 1,
        norm_pct_high: int   = 99,
        ema_alpha:     float = 0.3,
    ) -> None:
        self.ae          = autoencoder
        self.enc         = encoder_model
        self.iso         = iso_forest
        self.scaler      = scaler
        self.feat_names  = list(feature_names)
        self.feat_arr    = np.array(feature_names)   # fast fancy-indexing
        self.top_n       = top_n
        self.ema_alpha   = ema_alpha
        self._pct_low    = norm_pct_low
        self._pct_high   = norm_pct_high

        # Percentile anchors — set by calibrate()
        self.ae_p_low:  float | None = None
        self.ae_p_high: float | None = None
        self.if_p_low:  float | None = None
        self.if_p_high: float | None = None

    # ── Calibration ──────────────────────────────────────────────────────────

    def calibrate(self, X_train_scaled: np.ndarray) -> None:
        """
        Fit normalization anchors on benign-only training data (X_train).

        Must be called once before any scoring. Pass X_train (Monday
        benign-only), NOT all of X_mon, to keep the baseline clean.

        Computes the [norm_pct_low, norm_pct_high] percentiles of the AE MSE
        and IF score distributions on benign data. These anchors are used by
        _norm() to map all future scores to [0, 1].
        """
        if len(X_train_scaled) == 0:
            raise ValueError("X_train_scaled is empty.")

        print(f"[SeverityScorer] Calibrating on {len(X_train_scaled):,} benign rows ...")
        print(f"  Percentile anchors : [{self._pct_low}th, {self._pct_high}th]")

        # AE reconstruction error on benign baseline
        X_hat  = self.ae.predict(X_train_scaled, batch_size=512, verbose=0)
        ae_mse = np.mean(np.square(X_train_scaled - X_hat), axis=1)
        self.ae_p_low  = float(np.percentile(ae_mse, self._pct_low))
        self.ae_p_high = float(np.percentile(ae_mse, self._pct_high))

        # IF isolation score on benign baseline
        if_raw = -self.iso.score_samples(X_train_scaled)
        self.if_p_low  = float(np.percentile(if_raw, self._pct_low))
        self.if_p_high = float(np.percentile(if_raw, self._pct_high))

        print(f"  AE MSE  p{self._pct_low}/p{self._pct_high} : "
              f"{self.ae_p_low:.6f} / {self.ae_p_high:.6f}")
        print(f"  IF raw  p{self._pct_low}/p{self._pct_high} : "
              f"{self.if_p_low:.6f} / {self.if_p_high:.6f}")
        print("  Calibration complete.\n")

    # ── score_row: single-row API ─────────────────────────────────────────────

    def score_row(self, x: np.ndarray) -> tuple[float, dict[str, Any]]:
        """
        Score a single scaled feature vector.

        Parameters
        ----------
        x : np.ndarray, shape (n_features,)

        Returns
        -------
        severity_score : float ∈ [0, 1]
            Directly passable to TrustDriftEngine.update(severity_score).

        diagnostics : dict
            Structured signals for the Explainability Module.

            {
                "severity_score": float,
                "ae_score":       float,
                "if_score":       float,
                "weights": {
                    "ae": float,
                    "if": float,
                },
                "top_features":   list[str],     # top-N by |x - x_hat|
                "feature_errors": list[float],   # |x - x_hat| all features
            }
        """
        self._require_calibrated()
        batch = self._score_batch_raw(x.reshape(1, -1))

        ae_sev   = float(batch["ae_sev"][0])
        if_sev   = float(batch["if_sev"][0])
        w_ae     = float(batch["w_ae"][0])
        w_if     = float(batch["w_if"][0])
        combined = float(batch["combined"][0])

        feat_abs = batch["feat_abs"][0]                    # (n_features,) absolute errors
        top_idx  = np.argsort(feat_abs)[::-1][: self.top_n]

        diagnostics: dict[str, Any] = {
            "severity_score": round(combined, 6),
            "ae_score":       round(ae_sev,  6),
            "if_score":       round(if_sev,  6),
            "weights": {
                "ae": round(w_ae, 6),
                "if": round(w_if, 6),
            },
            "top_features":   [self.feat_names[i] for i in top_idx],
            "feature_errors": [round(float(e), 6) for e in feat_abs],
        }
        return combined, diagnostics

    # ── score_batch: vectorized batch ────────────────────────────────────────

    def score_batch(self, X_scaled: np.ndarray) -> pd.DataFrame:
        """
        Score a 2-D array. Returns a DataFrame with all diagnostic columns.

        Columns
        -------
        ae_severity         [0,1]   normalized AE reconstruction signal
        if_severity         [0,1]   normalized IF isolation signal
        ae_raw_score        float   raw AE MSE (pre-normalization, for audit)
        if_raw_score        float   raw IF score (pre-normalization, for audit)
        weight_ae           float   dynamic weight given to AE this row
        weight_if           float   dynamic weight given to IF this row
        combined_severity   [0,1]   final score → TrustDriftEngine.update()
        explain_driver      str     'AE' or 'IF' — which sensor dominated
        top_feature_1..N    str     most anomalous features by |x - x_hat|
        top_error_1..N      float   their absolute reconstruction errors
        feat_err_0..M       float   |x - x_hat| for every feature
                                    (needed by score_row diagnostics dict)
        """
        self._require_calibrated()
        raw = self._score_batch_raw(X_scaled)

        n         = len(X_scaled)
        ae_sev    = raw["ae_sev"]
        if_sev    = raw["if_sev"]
        w_ae      = raw["w_ae"]
        w_if      = raw["w_if"]
        combined  = raw["combined"]
        feat_abs  = raw["feat_abs"]          # (n, n_features)
        ae_raw    = raw["ae_raw"]
        if_raw    = raw["if_raw"]

        # explain driver
        explain_driver = np.where(ae_sev >= if_sev, "AE", "IF")

        # top-N features (vectorized)
        top_idx      = np.argsort(feat_abs, axis=1)[:, -self.top_n:][:, ::-1]
        top_feat_mat = self.feat_arr[top_idx]
        row_idx      = np.arange(n)[:, None]
        top_err_mat  = feat_abs[row_idx, top_idx]

        result = pd.DataFrame({
            "ae_severity":       ae_sev.astype(np.float32),
            "if_severity":       if_sev.astype(np.float32),
            "ae_raw_score":      ae_raw.astype(np.float32),
            "if_raw_score":      if_raw.astype(np.float32),
            "weight_ae":         w_ae.astype(np.float32),
            "weight_if":         w_if.astype(np.float32),
            "combined_severity": combined.astype(np.float32),
            "explain_driver":    explain_driver,
        })

        for i in range(self.top_n):
            result[f"top_feature_{i+1}"] = top_feat_mat[:, i]
            result[f"top_error_{i+1}"]   = top_err_mat[:, i].astype(np.float32)

        for j in range(len(self.feat_names)):
            result[f"feat_err_{j}"] = feat_abs[:, j].astype(np.float32)

        return result

    # ── score_dataset: batched full-dataset scoring ───────────────────────────

    def score_dataset(
        self,
        X_scaled:     np.ndarray,
        y_true:       np.ndarray,
        attack_types: np.ndarray,
        name:         str,
        batch_size:   int   = 4096,
        smooth:       bool  = True,
    ) -> pd.DataFrame:
        """
        Score a full dataset in batches with optional EMA smoothing.

        EMA smoothing on combined_severity:
            smoothed(t) = α × raw(t) + (1−α) × smoothed(t−1)

        Stabilises Trust Engine input — a single noisy packet will not
        cause a sharp trust spike. Set smooth=False to disable.
        Original un-smoothed score is kept as 'severity_raw'.

        Returns all score_batch columns plus:
            flow_index     int    row index in original dataset
            true_label     int    ground-truth binary label
            attack_type    str    original label string
            severity_raw   float  un-smoothed combined_severity
        """
        n_rows, batches = len(X_scaled), []
        print(f"[SeverityScorer] Scoring {name} ({n_rows:,} rows) ...")

        for start in range(0, n_rows, batch_size):
            end   = min(start + batch_size, n_rows)
            chunk = self.score_batch(X_scaled[start:end])
            chunk.insert(0, "flow_index",  np.arange(start, end, dtype=int))
            chunk.insert(1, "true_label",  y_true[start:end].astype(int))
            chunk.insert(2, "attack_type", attack_types[start:end])
            batches.append(chunk)
            print(f"  {end:>7,} / {n_rows:,}  ({end/n_rows*100:.1f}%)", end="\r")

        print()
        df = pd.concat(batches, ignore_index=True)

        # EMA smoothing
        if smooth and self.ema_alpha > 0:
            raw      = df["combined_severity"].values.copy()
            df["severity_raw"] = raw.astype(np.float32)
            smoothed = raw.copy()
            a = self.ema_alpha
            for i in range(1, len(smoothed)):
                smoothed[i] = a * raw[i] + (1 - a) * smoothed[i - 1]
            df["combined_severity"] = smoothed.astype(np.float32)
        else:
            df["severity_raw"] = df["combined_severity"]

        return df

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _require_calibrated(self) -> None:
        if self.ae_p_low is None:
            raise RuntimeError(
                "Call scorer.calibrate(X_train_scaled) before scoring."
            )

    def _norm(
        self, arr: np.ndarray, p_low: float, p_high: float
    ) -> np.ndarray:
        """
        Robust vectorized normalization → [0, 1].

            norm(x) = clip( (x − p_low) / (p_high − p_low),  0,  1 )

        Values below p_low  → 0.0  (safely benign)
        Values above p_high → 1.0  (clipped, not collapsed)
        Values between      → smooth gradient
        """
        span = p_high - p_low
        if span <= 0:
            return np.zeros_like(arr, dtype=np.float32)
        return np.clip((arr - p_low) / span, 0.0, 1.0).astype(np.float32)

    def _score_batch_raw(self, X_scaled: np.ndarray) -> dict[str, np.ndarray]:
        """
        Core computation shared by score_row and score_batch.
        Returns a dict of raw arrays — callers format as needed.
        """
        # AE reconstruction
        X_hat    = self.ae.predict(X_scaled, batch_size=512, verbose=0)
        feat_abs = np.abs(X_scaled - X_hat)                  # |x - x_hat|, (n, feats)
        ae_raw   = np.mean(np.square(X_scaled - X_hat), axis=1)  # MSE per row

        ae_sev = self._norm(ae_raw, self.ae_p_low, self.ae_p_high)

        # IF isolation score
        if_raw = -self.iso.score_samples(X_scaled)
        if_sev = self._norm(if_raw, self.if_p_low, self.if_p_high)

        # Dynamic per-row weighting
        eps   = 1e-9
        denom = ae_sev + if_sev + eps
        w_ae  = (ae_sev / denom).astype(np.float32)
        w_if  = (1.0 - w_ae).astype(np.float32)

        combined = (w_ae * ae_sev + w_if * if_sev).astype(np.float32)

        return {
            "ae_sev":   ae_sev,
            "if_sev":   if_sev,
            "ae_raw":   ae_raw,
            "if_raw":   if_raw,
            "w_ae":     w_ae,
            "w_if":     w_if,
            "combined": combined,
            "feat_abs": feat_abs,
        }

    def __repr__(self) -> str:
        calibrated = self.ae_p_low is not None
        return (
            f"SeverityScorer("
            f"features={len(self.feat_names)}, "
            f"top_n={self.top_n}, "
            f"pct=[{self._pct_low},{self._pct_high}], "
            f"ema_alpha={self.ema_alpha}, "
            f"calibrated={calibrated})"
        )
