"""Offline model training script generating synthetic traffic and saving Isolation Forest."""

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_OUTPUT_PATH = Path(__file__).parent.parent / "app" / "trust_engine" / "model.joblib"


def generate_synthetic_training_data(n_samples: int = 5000) -> np.ndarray:
    """Generate synthetic normal and slightly noisy benign traffic feature vectors.

    Layout: [rate_1m, rate_5m, geo_vel, device_mismatch, time_dev, hop_count, novelty, shortcut]
    """
    rng = np.random.default_rng(seed=42)

    # 1. Normal low/moderate request rates (Poisson)
    rate_1m = rng.poisson(lam=3.0, size=(n_samples, 1))
    rate_5m = rate_1m * 4.2 + rng.normal(0, 1.5, size=(n_samples, 1))
    rate_5m = np.clip(rate_5m, 0, None)

    # 2. Geo-velocity: zero or normal commute speeds (< 60 km/h)
    geo_vel = rng.exponential(scale=5.0, size=(n_samples, 1))
    geo_vel = np.clip(geo_vel, 0, 120.0)

    # 3. Device mismatch: rare benign device shifts (0.01 probability)
    device_mismatch = rng.choice([0.0, 1.0], size=(n_samples, 1), p=[0.98, 0.02])

    # 4. Time of day deviation: mostly within working hours (low deviation)
    time_dev = rng.exponential(scale=0.08, size=(n_samples, 1))
    time_dev = np.clip(time_dev, 0.0, 1.0)

    # 5. Graph hop count: standard ReBAC paths (1-3 hops)
    hop_count = rng.choice([1, 2, 3], size=(n_samples, 1), p=[0.25, 0.65, 0.10])

    # 6. Path novelty: mostly familiar paths
    novelty = rng.choice([0.0, 1.0], size=(n_samples, 1), p=[0.95, 0.05])

    # 7. Privilege shortcut: no unauthorized shortcuts in benign dataset
    shortcut = np.zeros((n_samples, 1))

    return np.hstack(
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


def main() -> None:
    """Train Isolation Forest on synthetic dataset and save artifact."""
    print("Generating synthetic baseline traffic dataset...")
    x_train = generate_synthetic_training_data()

    print(f"Training Isolation Forest on {x_train.shape[0]} samples...")
    clf = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    clf.fit(x_train)

    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_OUTPUT_PATH)
    print(f"Successfully saved trained model artifact to {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
