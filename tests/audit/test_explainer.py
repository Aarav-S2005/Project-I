"""Unit tests for SHAP feature attribution and explainability."""

import pytest

from app.audit.explainer import SHAPExplainer
from app.common.schemas import BehavioralFeatures, FeatureVector, GraphFeatures
from app.trust_engine.model import AnomalyModel


class TestSHAPExplainer:
    """Test SHAP attribution calculation and ranking."""

    @pytest.fixture
    def anomaly_model(self) -> AnomalyModel:
        return AnomalyModel()

    def test_explain_normal_vector(self, anomaly_model: AnomalyModel) -> None:
        explainer = SHAPExplainer(model=anomaly_model)

        normal_vec = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=2.0,
                request_rate_5m=8.0,
                geo_velocity_kmh=0.0,
                device_fingerprint_mismatch=0.0,
                time_of_day_deviation=0.0,
            ),
            graph=GraphFeatures(
                hop_count=2,
                path_novelty_score=0.0,
                privilege_shortcut_flag=0.0,
                traversal_path_signature="user:a->team:b#member->doc:c#view",
            ),
        )

        attributions = explainer.explain(normal_vec)

        assert len(attributions) == 8
        # Check that attributions are sorted by contribution magnitude descending
        for i in range(len(attributions) - 1):
            assert attributions[i].contribution_score >= attributions[i + 1].contribution_score

    def test_explain_anomalous_vector(self, anomaly_model: AnomalyModel) -> None:
        explainer = SHAPExplainer(model=anomaly_model)

        anom_vec = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=180.0,
                request_rate_5m=600.0,
                geo_velocity_kmh=800.0,
                device_fingerprint_mismatch=1.0,
                time_of_day_deviation=0.9,
            ),
            graph=GraphFeatures(
                hop_count=1,
                path_novelty_score=1.0,
                privilege_shortcut_flag=1.0,
                traversal_path_signature="user:a->doc:c#owner",
            ),
        )

        attributions = explainer.explain(anom_vec)

        assert len(attributions) == 8
        # At least one feature should be identified as driving anomaly
        anomalous_drivers = [a for a in attributions if a.direction == "anomalous"]
        assert len(anomalous_drivers) > 0

    def test_explain_fallback_heuristics(self) -> None:
        # Explainer with no valid underlying model to trigger fallback
        explainer = SHAPExplainer()
        explainer._explainer = None  # force fallback

        test_vec = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=50.0,
                request_rate_5m=150.0,
                geo_velocity_kmh=0.0,
                device_fingerprint_mismatch=0.0,
                time_of_day_deviation=0.0,
            ),
            graph=GraphFeatures(
                hop_count=2,
                path_novelty_score=0.0,
                privilege_shortcut_flag=0.0,
                traversal_path_signature="",
            ),
        )

        attributions = explainer.explain(test_vec)
        assert len(attributions) == 8
        assert attributions[0].feature_name in FeatureVector.FEATURE_NAMES
