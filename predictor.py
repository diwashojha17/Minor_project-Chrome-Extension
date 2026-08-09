"""
predictor.py

Loads the trained Decision Tree model and predicts
the overall website security risk.

Model files:

Backend/
    model/
        decision_tree_model.pkl
        model_columns.json
"""

import json
import os
from typing import Dict, Any

import joblib
import pandas as pd

from feature_extractor import (
    FEATURE_ORDER,
    normalize_features,
)


# ============================================================
# DEFAULT MODEL PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DEFAULT_MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "decision_tree_model.pkl",
)

DEFAULT_COLUMNS_PATH = os.path.join(
    BASE_DIR,
    "model",
    "model_columns.json",
)


# ============================================================
# RISK WEIGHTS
# ============================================================

SEVERITY_WEIGHTS = {
    "SAFE": 0,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100,
}


# ============================================================
# PREDICTOR
# ============================================================

class VulnerabilityPredictor:

    def __init__(
        self,
        model_path=None,
        columns_path=None
    ):

        # Use configured path if it actually exists.
        # Otherwise use Backend/model/.
        if (
            model_path and
            os.path.exists(model_path)
        ):
            self.model_path = model_path
        else:
            self.model_path = (
                DEFAULT_MODEL_PATH
            )

        if (
            columns_path and
            os.path.exists(columns_path)
        ):
            self.columns_path = (
                columns_path
            )
        else:
            self.columns_path = (
                DEFAULT_COLUMNS_PATH
            )

        self.model = None

        self.columns = (
            FEATURE_ORDER.copy()
        )

        print(
            "[Predictor] Model path:",
            self.model_path
        )

        print(
            "[Predictor] Columns path:",
            self.columns_path
        )

        self._load_if_available()


    # ========================================================
    # LOAD MODEL
    # ========================================================

    def _load_if_available(self):

        if not os.path.exists(
            self.model_path
        ):
            print(
                "[Predictor] Model file not found:"
            )

            print(
                self.model_path
            )

            self.model = None
            return False


        try:

            print(
                "[Predictor] Loading Decision Tree..."
            )

            self.model = joblib.load(
                self.model_path
            )


            # --------------------------------------------
            # LOAD COLUMN ORDER
            # --------------------------------------------

            if os.path.exists(
                self.columns_path
            ):

                with open(
                    self.columns_path,
                    "r",
                    encoding="utf-8"
                ) as file:

                    saved_columns = (
                        json.load(file)
                    )

                if not isinstance(
                    saved_columns,
                    list
                ):
                    raise ValueError(
                        "model_columns.json must "
                        "contain a JSON list."
                    )

                self.columns = (
                    saved_columns
                )

            else:

                print(
                    "[Predictor] "
                    "model_columns.json not found. "
                    "Using FEATURE_ORDER."
                )

                self.columns = (
                    FEATURE_ORDER.copy()
                )


            # --------------------------------------------
            # VALIDATE
            # --------------------------------------------

            self._validate_model_schema()


            print(
                "[Predictor] Decision Tree loaded successfully."
            )

            print(
                "[Predictor] Feature count:",
                len(self.columns)
            )

            print(
                "[Predictor] Classes:",
                list(
                    self.model.classes_
                )
            )

            return True


        except Exception as error:

            print(
                "[Predictor] MODEL LOAD ERROR:"
            )

            print(
                repr(error)
            )

            self.model = None

            return False


    # ========================================================
    # VALIDATE MODEL
    # ========================================================

    def _validate_model_schema(self):

        if (
            list(self.columns) !=
            list(FEATURE_ORDER)
        ):
            raise ValueError(
                "model_columns.json does not "
                "match FEATURE_ORDER in "
                "feature_extractor.py."
            )


        if hasattr(
            self.model,
            "n_features_in_"
        ):

            actual = int(
                self.model.n_features_in_
            )

            expected = len(
                FEATURE_ORDER
            )

            if actual != expected:

                raise ValueError(
                    f"Decision Tree expects "
                    f"{actual} features but "
                    f"the extension uses "
                    f"{expected} features."
                )


    # ========================================================
    # MODEL READY
    # ========================================================

    def is_ready(self) -> bool:

        # Lazy reload:
        # useful if training happened after Flask started.

        if (
            self.model is None and
            os.path.exists(
                self.model_path
            )
        ):
            self._load_if_available()

        return (
            self.model is not None
        )


    # ========================================================
    # MANUAL RELOAD
    # ========================================================

    def reload_model(self):

        self.model = None

        self.columns = (
            FEATURE_ORDER.copy()
        )

        self._load_if_available()

        return (
            self.model is not None
        )


    # ========================================================
    # RISK SCORE
    # ========================================================

    def _calculate_risk_score(
        self,
        probabilities: Dict[str, float]
    ) -> float:

        weighted_score = 0.0
        total_probability = 0.0

        for (
            label,
            probability
        ) in probabilities.items():

            normalized_label = (
                str(label)
                .strip()
                .upper()
            )

            if (
                normalized_label
                not in
                SEVERITY_WEIGHTS
            ):
                continue

            weight = (
                SEVERITY_WEIGHTS[
                    normalized_label
                ]
            )

            weighted_score += (
                weight *
                float(probability)
            )

            total_probability += (
                float(probability)
            )


        if total_probability <= 0:
            return 0.0


        score = (
            weighted_score /
            total_probability
        )


        return round(
            max(
                0.0,
                min(
                    100.0,
                    score
                )
            ),
            2
        )


    # ========================================================
    # PREDICTION
    # ========================================================

    def predict(
        self,
        raw_features: Dict[str, Any]
    ) -> Dict[str, Any]:

        if not self.is_ready():

            raise RuntimeError(
                "Decision Tree model is "
                "not available."
            )


        # --------------------------------------------
        # NORMALIZE FEATURES
        # --------------------------------------------

        normalized = (
            normalize_features(
                raw_features
            )
        )


        # --------------------------------------------
        # EXACT TRAINING ORDER
        # --------------------------------------------

        feature_values = []

        for column in self.columns:

            feature_values.append(
                normalized.get(
                    column,
                    0
                )
            )


        X = pd.DataFrame(
            [feature_values],
            columns=self.columns
        )


        # --------------------------------------------
        # DECISION TREE PREDICTION
        # --------------------------------------------

        prediction = (
            self.model.predict(X)[0]
        )


        probabilities_array = (
            self.model.predict_proba(X)[0]
        )


        classes = (
            self.model.classes_
        )


        # --------------------------------------------
        # PROBABILITY MAP
        # --------------------------------------------

        probability_map = {}

        for (
            class_name,
            probability
        ) in zip(
            classes,
            probabilities_array
        ):

            label_name = (
                str(class_name)
                .strip()
                .upper()
            )

            probability_map[
                label_name
            ] = round(
                float(probability),
                6
            )


        # --------------------------------------------
        # LABEL
        # --------------------------------------------

        predicted_label = (
            str(prediction)
            .strip()
            .upper()
        )


        # --------------------------------------------
        # CONFIDENCE
        # --------------------------------------------

        confidence = float(
            max(
                probabilities_array
            )
        )


        # --------------------------------------------
        # SCORES
        # --------------------------------------------

        risk_score = (
            self._calculate_risk_score(
                probability_map
            )
        )


        security_score = round(
            100.0 -
            risk_score,
            2
        )


        # --------------------------------------------
        # RESULT
        # --------------------------------------------

        return {

            "label":
                predicted_label,

            "riskLevel":
                predicted_label,

            "risk_level":
                predicted_label,


            "confidence":
                round(
                    confidence,
                    4
                ),


            "probabilities":
                probability_map,


            "score":
                risk_score,

            "riskScore":
                risk_score,

            "risk_score":
                risk_score,


            "securityScore":
                security_score,

            "security_score":
                security_score,


            "modelReady":
                True,
        }


    # ========================================================
    # FEATURE IMPORTANCE
    # ========================================================

    def feature_importances(
        self
    ) -> Dict[str, float]:

        if not self.is_ready():
            return {}


        if not hasattr(
            self.model,
            "feature_importances_"
        ):
            return {}


        importances = (
            self.model
            .feature_importances_
        )


        importance_map = {}

        for (
            feature,
            importance
        ) in zip(
            self.columns,
            importances
        ):

            importance_map[
                feature
            ] = float(
                importance
            )


        return dict(
            sorted(
                importance_map.items(),
                key=lambda item:
                    item[1],
                reverse=True
            )
        )