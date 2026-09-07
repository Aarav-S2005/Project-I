"""Anomaly detection model using Isolation Forest for continuous trust scoring."""

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.common.schemas import FeatureVector

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).parent / "model.joblib"


class AnomalyModel:
    """Anomaly detection model wrapper based on scikit-learn Isolation Forest."""

    def __init__(self, model_path: Path | str | None = None) -> None:
        """Initialize and load or train baseline Isolation Forest model.

        Args:
            model_path: Optional path to serialized model artifact (.joblib).
        """
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self._model: IsolationForest | None = None
        self._load_or_initialize()

    @property
    def model(self) -> IsolationForest:
        """Get the underlying scikit-learn IsolationForest instance."""
        if self._model is None:
            raise RuntimeError("AnomalyModel is not initialized.")
        return self._model

    def _load_or_initialize(self) -> None:
        """Load trained artifact from disk, or initialize with synthetic baseline."""
        if self.model_path.exists():
            try:
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, IsolationForest):
                    self._model = loaded
                    logger.info("Loaded anomaly model from %s", self.model_path)
                    return
            except Exception as exc:
                logger.warning("Failed loading model from %s: %s", self.model_path, exc)

        # Fallback to training a default baseline model
        logger.info("Training initial baseline Isolation Forest model...")
        self._model = self._generate_baseline_model()

    def _generate_baseline_model(self) -> IsolationForest:
        """Generate and train an Isolation Forest on representative normal traffic."""
        rng = np.random.default_rng(seed=42)
        n_samples = 1000

        # Feature layout:
        # [rate_1m, rate_5m, geo_vel, device_mismatch, time_dev, hop_count, novelty, shortcut]
        rate_1m = rng.poisson(lam=2.0, size=(n_samples, 1))
        rate_5m = rate_1m * 4.5 + rng.normal(0, 1.0, size=(n_samples, 1))
        rate_5m = np.clip(rate_5m, 0, None)
        geo_vel = np.zeros((n_samples, 1))  # static/low speed by default
        device_mismatch = np.zeros((n_samples, 1))
        time_dev = rng.uniform(0.0, 0.1, size=(n_samples, 1))  # mostly normal hours
        hop_count = rng.choice([1, 2, 3], size=(n_samples, 1), p=[0.3, 0.6, 0.1])
        novelty = np.zeros((n_samples, 1))  # mostly familiar paths
        shortcut = np.zeros((n_samples, 1))

        x_normal = np.hstack(
            [
                rate_1m,
                rate_5m,
                geo_vel,
                device_mismatch,
                time_dev,
                hop_count,
                novelty,
                shortcut,
            ]
        )

        clf = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        clf.fit(x_normal)
        return clf

    def score_anomaly(self, features: FeatureVector | list[float] | np.ndarray[Any, Any]) -> float:
        """Compute normalized anomaly severity score between 0.0 (normal) and 1.0 (anomalous).

        Args:
            features: FeatureVector instance, raw list of floats, or numpy array.

        Returns:
            float: Anomaly severity score in [0.0, 1.0].
        """
        if isinstance(features, FeatureVector):
            x = np.array(features.to_feature_list(), dtype=float).reshape(1, -1)
        elif isinstance(features, list):
            x = np.array(features, dtype=float).reshape(1, -1)
        else:
            x = features.reshape(1, -1)

        # IsolationForest decision_function returns positive for inliers, negative for outliers
        raw_score = float(self.model.decision_function(x)[0])

        # Logistic sigmoid calibration mapping decision score to anomaly probability
        # When raw_score > 0.15 (typical inlier) -> anomaly_score < 0.15
        # When raw_score < -0.10 (severe outlier) -> anomaly_score > 0.85
        anomaly_score = 1.0 / (1.0 + np.exp(12.0 * raw_score))
        return float(np.clip(anomaly_score, 0.0, 1.0))

    def train(self, x_data: np.ndarray[Any, Any]) -> None:
        """Train Isolation Forest on provided feature dataset and persist artifact.

        Args:
            x_data: 2D numpy array of feature vectors (shape: [N, 8]).
        """
        clf = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        clf.fit(x_data)
        self._model = clf

        # Persist model artifact
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, self.model_path)
        logger.info("Trained and saved anomaly model to %s", self.model_path)
