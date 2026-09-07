"""Unit tests for Isolation Forest anomaly model wrapper."""

from pathlib import Path

import numpy as np
import pytest

from app.common.schemas import BehavioralFeatures, FeatureVector, GraphFeatures
from app.trust_engine.model import AnomalyModel


class TestAnomalyModel:
    """Test AnomalyModel training, inference, and persistence."""

    @pytest.fixture
    def anomaly_model(self, tmp_path: Path) -> AnomalyModel:
        model_file = tmp_path / "test_model.joblib"
        return AnomalyModel(model_path=model_file)

    def test_normal_sample_scoring(self, anomaly_model: AnomalyModel) -> None:
        # Typical benign feature vector
        normal_vec = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=2.0,
                request_rate_5m=9.0,
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

        score = anomaly_model.score_anomaly(normal_vec)
        assert 0.0 <= score <= 0.45

    def test_anomalous_sample_scoring(self, anomaly_model: AnomalyModel) -> None:
        # Severe anomaly: extreme rate burst, high geo-velocity, novel path, device mismatch
        anomalous_vec = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=150.0,
                request_rate_5m=400.0,
                geo_velocity_kmh=950.0,
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

        score = anomaly_model.score_anomaly(anomalous_vec)
        assert score > 0.50

    def test_train_and_save_model(self, tmp_path: Path) -> None:
        model_file = tmp_path / "saved_model.joblib"
        model = AnomalyModel(model_path=model_file)

        # Synthetic custom training data
        rng = np.random.default_rng(seed=123)
        x_data = rng.normal(0.0, 1.0, size=(200, 8))
        model.train(x_data)

        assert model_file.exists()

        # Reload from saved file
        reloaded = AnomalyModel(model_path=model_file)
        test_sample = [0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 0.0, 0.0]
        score = reloaded.score_anomaly(test_sample)
        assert 0.0 <= score <= 1.0
