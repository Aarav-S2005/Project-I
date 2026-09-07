"""SHAP-based feature-level attribution and explainability for anomaly decisions."""

import logging
from typing import Any

import numpy as np
import shap
from sklearn.ensemble import IsolationForest

from app.common.schemas import FeatureAttribution, FeatureVector
from app.trust_engine.model import AnomalyModel

logger = logging.getLogger(__name__)


class SHAPExplainer:
    """Computes SHAP feature attribution values for Isolation Forest anomaly decisions."""

    def __init__(self, model: AnomalyModel | IsolationForest | None = None) -> None:
        """Initialize explainer with target model instance.

        Args:
            model: AnomalyModel wrapper or raw IsolationForest instance.
        """
        self._explainer: shap.TreeExplainer | None = None
        self._underlying_model: IsolationForest | None = None
        if model is not None:
            self._set_model(model)

    def _set_model(self, model: AnomalyModel | IsolationForest) -> None:
        """Set model and initialize TreeExplainer."""
        if isinstance(model, AnomalyModel):
            self._underlying_model = model.model
        else:
            self._underlying_model = model

        try:
            self._explainer = shap.TreeExplainer(self._underlying_model)
        except Exception as exc:
            logger.warning("Failed initializing SHAP TreeExplainer: %s", exc)
            self._explainer = None

    def explain(
        self,
        features: FeatureVector,
        model: AnomalyModel | IsolationForest | None = None,
    ) -> list[FeatureAttribution]:
        """Compute feature attributions explaining the model anomaly score.

        In IsolationForest, negative SHAP values reduce the decision function,
        indicating that a feature pushed the observation towards being an anomaly.

        Args:
            features: FeatureVector containing all 8 behavioral and graph features.
            model: Optional model override.

        Returns:
            list[FeatureAttribution]: Ranked list of feature attributions (highest impact first).
        """
        if model is not None:
            self._set_model(model)
        elif self._explainer is None:
            # Fallback to default AnomalyModel
            default_model = AnomalyModel()
            self._set_model(default_model)

        feat_list = features.to_feature_list()
        feat_names = FeatureVector.FEATURE_NAMES
        x_sample = np.array(feat_list, dtype=float).reshape(1, -1)

        raw_shap_values: np.ndarray[Any, Any] | None = None
        if self._explainer is not None:
            try:
                raw_shap = self._explainer.shap_values(x_sample)
                # Check shape: could be (1, 8) or (8,)
                raw_shap_values = np.array(raw_shap).reshape(-1)
            except Exception as exc:
                logger.warning("SHAP computation failed, falling back to heuristics: %s", exc)

        if raw_shap_values is None or len(raw_shap_values) != len(feat_names):
            # Fallback: heuristic attribution based on feature values
            raw_shap_values = self._heuristic_attribution(feat_list)

        # Normalize contribution scores
        total_mag = float(np.sum(np.abs(raw_shap_values))) or 1.0
        attributions: list[FeatureAttribution] = []

        for name, val, s_val in zip(feat_names, feat_list, raw_shap_values, strict=True):
            # Negative SHAP value in IsolationForest indicates anomaly push
            is_anomalous = bool(s_val < 0.0)
            norm_contrib = round(abs(float(s_val)) / total_mag, 4)

            attributions.append(
                FeatureAttribution(
                    feature_name=name,
                    feature_value=round(float(val), 3),
                    shap_value=round(float(s_val), 4),
                    contribution_score=norm_contrib,
                    direction="anomalous" if is_anomalous else "benign",
                )
            )

        # Sort by absolute impact (highest contribution first)
        attributions.sort(key=lambda a: a.contribution_score, reverse=True)
        return attributions

    def _heuristic_attribution(self, feat_list: list[float]) -> np.ndarray[Any, Any]:
        """Heuristic attribution fallback if SHAP TreeExplainer fails."""
        # Baseline reference means
        baseline_means = np.array([2.0, 8.0, 0.0, 0.0, 0.0, 2.0, 0.0, 0.0], dtype=float)
        deviations = np.array(feat_list, dtype=float) - baseline_means
        # Invert so positive deviation (higher anomaly) produces negative attribution
        result: np.ndarray[Any, Any] = np.array(-np.abs(deviations) * 0.1, dtype=float)
        return result
