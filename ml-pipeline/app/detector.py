"""
IoT Security Gateway - ML Pipeline Detector

Loads trained Isolation Forest models from the models directory and
provide a single score() method that returns an anomaly score for a
given device's feature vector.

Model file naming convention
-----------------------------
Models are saved as joblib files by the offline training script
(train/train.py). The naming convention is:

  <mac_sanitised>.joblib   - per-device model (e.g. aa_bb_cc_dd_ee_ff.joblib)
  _fleet.joblib            - global fleet model, used as a fallback when no
                             per-device model exists for a newly-joined device.

Both file types are loaded from the directory specified by MODELS_DIR
(default: /opt/ml-pipeline/models/).

Anomaly scores
--------------
scikit-learn's IsolationForest.decision_function() returns a score where:
  - Positive values (near +0.5) indicate normal behaviour.
  - Values near 0 are ambiguous.
  - Negative values (near -0.5 or below) indicate anomalies.

This convention is inverted to produce an "anomaly score" where higher = more
anomalous, by computing: anomaly_score = -decision_function_output.

The thresholds in config/thresholds.yml are then expressed as positive numbers
for intuitive readability.
"""

import logging
import os

import joblib
import numpy as np

from features import FEATURE_NAMES, to_vector

LOG = logging.getLogger(__name__)

# Default path to the directory containing trained model files.
MODELS_DIR = os.environ.get("MODELS_DIR", "/opt/ml-pipeline/models")


class Detector:
    """
    Wraps one or more Isolation Forest models and provides anomaly scoring.

    All .joblib files are loaded from the models directory at startup. Models
    can be reloaded at runtime by calling reload().
    """

    def __init__(self, models_dir: str = MODELS_DIR) -> None:
        self.models_dir = models_dir

        # Per-device models keyed by sanitised MAC (e.g. "aa_bb_cc_dd_ee_ff").
        self._device_models: dict[str, object] = {}

        # Global fleet model used as a fallback.
        self._fleet_model: object | None = None

        self.reload()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """
        Scan the models directory and load all .joblib files.

        Safe to call at runtime (e.g., after placing new model files).
        Logs a warning if the directory doesn't exist yet - this is
        expected behaviour before training has been run.
        """
        if not os.path.isdir(self.models_dir):
            LOG.warning(
                "Models directory does not exist: %s. "
                "The pipeline will run without ML scoring until models are trained.",
                self.models_dir,
            )
            return

        loaded_device = 0
        loaded_fleet  = 0

        for filename in os.listdir(self.models_dir):
            if not filename.endswith(".joblib"):
                continue

            path = os.path.join(self.models_dir, filename)
            try:
                model = joblib.load(path)
            except Exception as exc:
                LOG.error("Failed to load model %s: %s", path, exc)
                continue

            stem = filename[:-7]  # strip .joblib

            if stem == "_fleet":
                self._fleet_model = model
                loaded_fleet += 1
                LOG.info("Loaded fleet model from %s.", filename)
            else:
                self._device_models[stem] = model
                loaded_device += 1

        LOG.info(
            "Model reload complete: %d per-device model(s), %d fleet model(s).",
            loaded_device, loaded_fleet,
        )

    def score(self, mac: str, features: dict[str, float]) -> float | None:
        """
        Return an anomaly score in the range [0, 1+] for a device.

        Higher scores indicate more anomalous behaviour.

        Returns None if no model is available for the device (and no fleet
        model exists), so the caller can skip alert classification.
        """
        model = self._select_model(mac)
        if model is None:
            return None

        vector = np.array([to_vector(features)], dtype=np.float64)

        try:
            # decision_function returns negative for anomalies.
            # I invert the sign so that higher = more anomalous.
            raw_score = model.decision_function(vector)[0]
            anomaly_score = float(-raw_score)
            return anomaly_score
        except Exception as exc:
            LOG.error("Inference failed for %s: %s", mac, exc)
            return None

    def has_model(self, mac: str) -> bool:
        """Return True if a per-device or fleet model is available."""
        return self._select_model(mac) is not None

    def model_type(self, mac: str) -> str:
        """Return 'per-device', 'fleet', or 'none' for the model being used."""
        key = _mac_to_key(mac)
        if key in self._device_models:
            return "per-device"
        if self._fleet_model is not None:
            return "fleet"
        return "none"

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _select_model(self, mac: str) -> object | None:
        """Return the best available model for a device."""
        key = _mac_to_key(mac)
        if key in self._device_models:
            return self._device_models[key]
        return self._fleet_model


def _mac_to_key(mac: str) -> str:
    """
    Convert a MAC address to a model filename key.

    aa:bb:cc:dd:ee:ff  ->  aa_bb_cc_dd_ee_ff
    """
    return mac.lower().replace(":", "_")
