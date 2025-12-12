import torch
import numpy as np
import logging
import os
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from collections import deque
from ..config import get_settings
from .detectors import (
    RuleBasedDetector,
    StatisticalFeatureDetector,
    SemanticDetector,
    MAMLDetector,
    MAMLConfig,
    DetectionResult,
    SecurityClass
)

# Model version for tracking
MODEL_VERSION = "3.1.0"  # Fixed ensemble weighting and calibration

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Random seed for reproducibility
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)


class ConfidenceCalibrator:
    """
    Platt scaling for confidence calibration.

    Ensures confidence scores from different detectors are comparable
    by fitting a sigmoid function to map raw scores to calibrated probabilities.

    Reference:
    - Platt, J. (1999). Probabilistic outputs for support vector machines.
    - Niculescu-Mizil & Caruana (2005). Predicting good probabilities with supervised learning.
    """

    def __init__(self):
        # Platt scaling parameters per detector: P(y=1|f) = 1 / (1 + exp(A*f + B))
        self.platt_params: Dict[str, Tuple[float, float]] = {}
        # Calibration data: (raw_score, actual_label)
        self.calibration_data: Dict[str, List[Tuple[float, int]]] = {}
        self.min_samples_for_calibration = 30
        self.is_calibrated: Dict[str, bool] = {}

    def add_sample(self, detector_name: str, confidence: float, ground_truth: str):
        """Add a sample for calibration."""
        if detector_name not in self.calibration_data:
            self.calibration_data[detector_name] = []
            self.is_calibrated[detector_name] = False

        # Convert ground truth to binary (1 = attack, 0 = benign)
        label = 1 if ground_truth == SecurityClass.ATTACK.value else 0
        self.calibration_data[detector_name].append((confidence, label))

        # Re-calibrate if we have enough samples
        if len(self.calibration_data[detector_name]) >= self.min_samples_for_calibration:
            self._fit_platt_scaling(detector_name)

    def _fit_platt_scaling(self, detector_name: str):
        """Fit Platt scaling parameters using logistic regression."""
        data = self.calibration_data[detector_name]
        if len(data) < self.min_samples_for_calibration:
            return

        scores = np.array([d[0] for d in data])
        labels = np.array([d[1] for d in data])

        # Use simplified Platt scaling: A=-1, B=0 initially
        # Then adjust based on observed calibration error
        try:
            from scipy.optimize import minimize

            def neg_log_likelihood(params):
                A, B = params
                probs = 1.0 / (1.0 + np.exp(A * scores + B))
                probs = np.clip(probs, 1e-10, 1 - 1e-10)
                return -np.sum(labels * np.log(probs) + (1 - labels) * np.log(1 - probs))

            result = minimize(neg_log_likelihood, [-1.0, 0.0], method='BFGS')
            self.platt_params[detector_name] = (result.x[0], result.x[1])
            self.is_calibrated[detector_name] = True
            logger.info(f"Calibrated {detector_name}: A={result.x[0]:.3f}, B={result.x[1]:.3f}")
        except Exception as e:
            logger.warning(f"Failed to calibrate {detector_name}: {e}")
            # Fallback to identity calibration
            self.platt_params[detector_name] = (-1.0, 0.0)
            self.is_calibrated[detector_name] = False

    def calibrate(self, detector_name: str, confidence: float, predicted_class: str) -> float:
        """
        Calibrate confidence score.

        Args:
            detector_name: Name of the detector
            confidence: Raw confidence score
            predicted_class: The class predicted by the detector

        Returns:
            Calibrated probability (attack probability if predicted attack, benign prob otherwise)
        """
        if detector_name not in self.platt_params:
            # No calibration available - use temperature scaling as fallback
            return self._temperature_calibrate(detector_name, confidence)

        A, B = self.platt_params[detector_name]
        calibrated = 1.0 / (1.0 + np.exp(A * confidence + B))

        # If predicting benign, return benign probability
        if predicted_class == SecurityClass.BENIGN.value:
            calibrated = 1.0 - calibrated

        return float(np.clip(calibrated, 0.0, 1.0))

    def _temperature_calibrate(self, detector_name: str, confidence: float) -> float:
        """Fallback temperature scaling calibration."""
        # Empirically tuned temperatures
        temperatures = {
            "rule_based": 1.0,    # Well-calibrated binary output
            "semantic": 1.2,      # Slightly overconfident
            "statistical": 1.4,   # More overconfident
            "maml": 1.1           # Softmax already calibrated-ish
        }
        temp = temperatures.get(detector_name, 1.2)

        # Temperature scaling: softmax(logit / T)
        # For single probability: p' = p^(1/T) / (p^(1/T) + (1-p)^(1/T))
        if confidence >= 1.0:
            return 1.0
        if confidence <= 0.0:
            return 0.0

        p_scaled = confidence ** (1.0 / temp)
        q_scaled = (1.0 - confidence) ** (1.0 / temp)
        return p_scaled / (p_scaled + q_scaled)


class BinaryMCPDetector:
    """
    Facade for binary security detection system with Dynamic Weighted Ensemble.

    Binary Classification:
    - BENIGN: Safe requests matching known good patterns
    - ATTACK: All threat types (injections, traversals, anomalies, policy violations)

    Ensemble Strategy:
    - Uses weighted voting based on detector reliability and confidence
    - Applies Platt scaling for confidence calibration (when ground truth available)
    - Falls back to temperature scaling when uncalibrated
    - Fail-safe behavior: Ambiguous cases default to ATTACK
    - Weight adjustment requires labeled samples (not just agreement)

    Detectors:
    1. Rule-Based: High-precision pattern matching for known attacks
    2. Statistical: Mahalanobis distance-based anomaly detection (pooled covariance)
    3. Semantic: DistilBERT prototypical learning with data-driven margins
    4. MAML (optional): Meta-learned few-shot adaptation
    """

    _instance = None
    _init_error: Optional[Exception] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BinaryMCPDetector, cls).__new__(cls)
            cls._instance._initialized = False
            cls._instance._init_error = None
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """
        Reset the singleton instance.

        Use this to recover from initialization failures or for testing.
        After calling this, the next __new__() will create a fresh instance.
        """
        cls._instance = None
        cls._init_error = None
        logger.info("BinaryMCPDetector singleton instance reset")

    def __init__(self):
        # If previously failed, re-raise the error
        if self._init_error is not None:
            raise RuntimeError(
                f"BinaryMCPDetector singleton initialization previously failed: {self._init_error}"
            ) from self._init_error

        if self._initialized:
            return

        try:
            self._do_init()
        except Exception as e:
            # Store the error and re-raise
            self._init_error = e
            logger.error(f"BinaryMCPDetector initialization failed: {e}")
            raise

    def _do_init(self):
        """Actual initialization logic, separated for error handling."""
        logger.info("Initializing BinaryMCPDetector (binary classification)...")
        self.settings = get_settings()

        # Set random seed for reproducibility
        np.random.seed(RANDOM_SEED)
        torch.manual_seed(RANDOM_SEED)

        # Initial detector weights (will be adjusted only with labeled data)
        self.detector_weights = {
            "rule_based": 0.40,     # High precision for known attacks
            "semantic": 0.35,       # Best generalization
            "statistical": 0.15,    # Statistical anomaly detection
            "maml": 0.10           # Meta-learning (if enabled)
        }

        # Store initial weights for reference
        self._initial_weights = dict(self.detector_weights)

        # Confidence calibrator (Platt scaling)
        self.calibrator = ConfidenceCalibrator()

        # Performance tracking with proper ground truth handling
        self.performance_tracker = {
            "predictions": deque(maxlen=1000),  # Use deque for efficient FIFO
            "labeled_predictions": deque(maxlen=500),  # Only predictions with ground truth
            "agreements": {},
        }

        # Initialize detection strategies
        self.rule_detector = RuleBasedDetector()
        self.stat_detector = StatisticalFeatureDetector(
            sigma=self.settings.detector_sigma,
            confidence_level=0.997  # 3-sigma equivalent
        )
        self.semantic_detector = SemanticDetector(
            model_name=self.settings.model_name,
            sigma=self.settings.detector_sigma
        )

        # Initialize MAML detector if enabled
        self.maml_detector: Optional[MAMLDetector] = None
        if self.settings.maml_enabled:
            maml_config = MAMLConfig(
                meta_lr=self.settings.maml_meta_lr,
                inner_lr=self.settings.maml_inner_lr,
                adaptation_steps=self.settings.maml_adaptation_steps,
                first_order=self.settings.maml_first_order,
                shots=self.settings.maml_shots,
                hidden_dim=self.settings.maml_hidden_dim,
                confidence_threshold=self.settings.maml_confidence_threshold,
                num_meta_epochs=self.settings.maml_num_meta_epochs
            )
            self.maml_detector = MAMLDetector(
                model_name=self.settings.model_name,
                config=maml_config
            )
            logger.info("  MAML detector enabled")

        self._initialized = True
        detectors = "rule, statistical, semantic"
        if self.maml_detector:
            detectors += ", maml"
        logger.info(f"Binary Detector loaded (benign vs attack)")
        logger.info(f"   Active detectors: {detectors}")
        logger.info(f"   Ensemble mode: Dynamic Weighted Voting with Platt Calibration")
        logger.info(f"   Initial Weights: Rule={self.detector_weights['rule_based']:.2f}, "
                   f"Semantic={self.detector_weights['semantic']:.2f}, "
                   f"Statistical={self.detector_weights['statistical']:.2f}")

    def fit(self, tool_name: str, benign_samples: List[str],
            attack_samples: Optional[List[str]] = None):
        """
        Train all sub-detectors with labeled samples.

        Args:
            tool_name: Name of the tool being trained
            benign_samples: Known safe requests
            attack_samples: Known attack patterns (all types merged)
        """
        self.stat_detector.fit(tool_name, benign_samples, attack_samples)
        self.semantic_detector.fit(tool_name, benign_samples, attack_samples)

        if self.maml_detector:
            self.maml_detector.fit(tool_name, benign_samples, attack_samples)

    def meta_train_maml(self, all_tool_data: Dict[str, Dict[str, List[str]]], verbose: bool = True):
        """
        Perform MAML meta-training across all tools.

        Args:
            all_tool_data: {tool_name: {"benign": [...], "attack": [...]}}
            verbose: Print training progress
        """
        if not self.maml_detector:
            logger.warning("MAML detector not enabled, skipping meta-training")
            return

        logger.info("Starting MAML meta-training...")
        self.maml_detector.meta_train(all_tool_data, verbose=verbose)
        logger.info("MAML meta-training complete")

    def _calibrate_confidence(self, confidence: float, detector_name: str, predicted_class: str) -> float:
        """Apply Platt scaling or temperature scaling for confidence calibration."""
        return self.calibrator.calibrate(detector_name, confidence, predicted_class)

    def _compute_ensemble_vote(self, votes: Dict[str, DetectionResult]) -> dict:
        """
        Compute weighted ensemble vote from detector predictions.

        Strategy:
        1. Calibrate confidences using Platt scaling (or temperature fallback)
        2. Apply detector weights
        3. Compute weighted vote for BENIGN vs ATTACK
        4. Apply fail-safe: ties and ambiguous cases -> ATTACK
        5. Report uncertainty when detectors strongly disagree
        """
        if not votes:
            return {
                "class": SecurityClass.ATTACK.value,
                "confidence": 0.5,
                "reason": "No detector predictions (fail-safe deny)",
                "allowed": False,
                "distance": None,
                "uncertainty": "high"
            }

        # Accumulate weighted votes per class
        class_votes = {
            SecurityClass.BENIGN.value: 0.0,
            SecurityClass.ATTACK.value: 0.0
        }
        class_reasons = {
            SecurityClass.BENIGN.value: [],
            SecurityClass.ATTACK.value: []
        }

        total_weight = 0.0
        detector_contributions = {}

        for detector_name, result in votes.items():
            weight = self.detector_weights.get(detector_name, 0.1)

            if weight <= 0:
                continue

            # Use calibrated confidence
            calibrated_conf = self._calibrate_confidence(
                result.confidence, detector_name, result.classification
            )
            weighted_conf = weight * calibrated_conf

            class_name = result.classification
            if class_name in class_votes:
                class_votes[class_name] += weighted_conf
                class_reasons[class_name].append(f"{detector_name}({calibrated_conf:.2f})")

            detector_contributions[detector_name] = {
                "class": class_name,
                "raw_confidence": result.confidence,
                "calibrated_confidence": calibrated_conf,
                "weight": weight,
                "contribution": weighted_conf
            }

            total_weight += weight

        if total_weight <= 0:
            return {
                "class": SecurityClass.ATTACK.value,
                "confidence": 0.5,
                "reason": "All detectors skipped (fail-safe deny)",
                "allowed": False,
                "distance": None,
                "uncertainty": "high"
            }

        # Normalize by total weight
        for class_name in class_votes:
            class_votes[class_name] /= total_weight

        benign_score = class_votes[SecurityClass.BENIGN.value]
        attack_score = class_votes[SecurityClass.ATTACK.value]

        # Compute disagreement for uncertainty estimation
        predictions = [r.classification for r in votes.values()]
        unique_predictions = set(predictions)
        disagreement = len(unique_predictions) > 1

        # Fail-safe: require clear benign majority
        margin = benign_score - attack_score

        if margin > 0.1:  # Benign wins with clear margin
            winning_class = SecurityClass.BENIGN.value
            winning_confidence = benign_score
            uncertainty = "low" if margin > 0.3 else "medium"
        else:  # Attack wins or tie -> fail-safe to attack
            winning_class = SecurityClass.ATTACK.value
            winning_confidence = max(attack_score, 0.5 + (0.1 - margin) * 2)
            uncertainty = "medium" if margin < 0 else "high"

        # High disagreement increases uncertainty
        if disagreement and uncertainty == "low":
            uncertainty = "medium"

        # Build explanation
        benign_str = ", ".join(class_reasons[SecurityClass.BENIGN.value]) or "none"
        attack_str = ", ".join(class_reasons[SecurityClass.ATTACK.value]) or "none"
        reason = f"Ensemble: benign({benign_score:.2f}: {benign_str}) vs attack({attack_score:.2f}: {attack_str})"

        if disagreement:
            reason += " [detectors disagree]"

        # Collect distance from semantic detector
        distance = None
        for detector_name, result in votes.items():
            if result.metadata and "distances" in result.metadata:
                distance = result.metadata["distances"]
                break

        return {
            "class": winning_class,
            "confidence": float(winning_confidence),
            "reason": reason,
            "allowed": winning_class == SecurityClass.BENIGN.value,
            "distance": distance,
            "uncertainty": uncertainty,
            "ensemble_details": detector_contributions,
            "margin": float(margin)
        }

    def predict(self, tool_name: str, payload: str) -> dict:
        """
        Binary ensemble prediction using dynamic weighted voting.

        Process:
        1. Collect predictions from all detectors
        2. Apply confidence calibration
        3. Compute weighted vote (BENIGN vs ATTACK)
        4. Apply fail-safe behavior for ambiguous cases

        Returns:
            dict with keys: class, confidence, reason, allowed, distance, uncertainty, ensemble_details
        """
        votes = {}

        # 1. Rule-Based Detection (High Precision)
        rule_result = self.rule_detector.predict(payload)
        if rule_result:
            votes["rule_based"] = rule_result
            # High-confidence rule match -> use directly
            if rule_result.classification == SecurityClass.ATTACK.value:
                if rule_result.confidence >= 0.9:
                    result = self._format_result(rule_result)
                    result["reason"] = f"[Rule-Based Definitive] {result['reason']}"
                    result["uncertainty"] = "low"
                    return result

        # 2. Statistical Classification
        stat_result = self.stat_detector.predict(payload, tool_name)
        if stat_result:
            votes["statistical"] = stat_result

        # 3. Semantic Classification
        semantic_result = self.semantic_detector.predict(payload, tool_name)
        if semantic_result:
            votes["semantic"] = semantic_result

        # 4. MAML Classification (if enabled)
        if self.maml_detector:
            maml_result = self.maml_detector.predict(payload, tool_name)
            if maml_result:
                votes["maml"] = maml_result

        # Track predictions
        detector_predictions = {name: result.classification for name, result in votes.items()}
        detector_confidences = {name: result.confidence for name, result in votes.items()}
        self._update_performance_tracker(detector_predictions, detector_confidences)

        return self._compute_ensemble_vote(votes)

    def _format_result(self, result: DetectionResult) -> dict:
        """Format detection result for API response."""
        return {
            "class": result.classification,
            "confidence": result.confidence,
            "reason": result.reason,
            "allowed": result.allowed,
            "distance": result.metadata.get("distances")
        }

    def _update_performance_tracker(
        self,
        predictions: Dict[str, str],
        confidences: Dict[str, float],
        ground_truth: Optional[str] = None
    ):
        """Track detector predictions for performance analysis."""
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "predictions": predictions,
            "confidences": confidences,
            "ground_truth": ground_truth
        }

        self.performance_tracker["predictions"].append(record)

        # Update agreement counts
        detector_names = list(predictions.keys())
        for i, det1 in enumerate(detector_names):
            for det2 in detector_names[i+1:]:
                key = f"{det1}_{det2}"
                if key not in self.performance_tracker["agreements"]:
                    self.performance_tracker["agreements"][key] = {"agree": 0, "disagree": 0}

                if predictions[det1] == predictions[det2]:
                    self.performance_tracker["agreements"][key]["agree"] += 1
                else:
                    self.performance_tracker["agreements"][key]["disagree"] += 1

    def _compute_detector_accuracy(self) -> Dict[str, Dict[str, float]]:
        """
        Compute accuracy metrics for each detector using ONLY labeled samples.

        Returns accuracy, precision, recall for each detector.
        """
        labeled = list(self.performance_tracker["labeled_predictions"])
        if not labeled:
            return {}

        metrics = {}

        # Aggregate per detector
        for detector in self.detector_weights.keys():
            tp, fp, tn, fn = 0, 0, 0, 0

            for record in labeled:
                if detector not in record["predictions"]:
                    continue

                pred = record["predictions"][detector]
                truth = record["ground_truth"]

                if pred == SecurityClass.ATTACK.value and truth == SecurityClass.ATTACK.value:
                    tp += 1
                elif pred == SecurityClass.ATTACK.value and truth == SecurityClass.BENIGN.value:
                    fp += 1
                elif pred == SecurityClass.BENIGN.value and truth == SecurityClass.BENIGN.value:
                    tn += 1
                else:  # pred benign, truth attack
                    fn += 1

            total = tp + fp + tn + fn
            if total == 0:
                continue

            accuracy = (tp + tn) / total
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

            metrics[detector] = {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "samples": total
            }

        return metrics

    def _adjust_weights_from_accuracy(self, min_samples: int = 50):
        """
        Adjust detector weights based on measured accuracy.

        IMPORTANT: This ONLY uses labeled samples with ground truth.
        Agreement-based adjustment was removed as it's methodologically flawed.
        """
        metrics = self._compute_detector_accuracy()

        if not metrics:
            logger.info("No labeled data available for weight adjustment")
            return

        # Check minimum samples per detector
        for detector, m in metrics.items():
            if m["samples"] < min_samples:
                logger.info(f"Insufficient labeled samples for {detector} ({m['samples']} < {min_samples})")
                return

        # Use F1 score for weight adjustment (balances precision and recall)
        f1_scores = {det: m["f1"] for det, m in metrics.items()}
        total_f1 = sum(f1_scores.values())

        if total_f1 <= 0:
            return

        # Dampen weight changes to avoid instability
        dampening = 0.8  # Keep 80% of old weight

        for detector, f1 in f1_scores.items():
            if detector in self.detector_weights:
                new_weight = f1 / total_f1
                old_weight = self.detector_weights[detector]
                self.detector_weights[detector] = dampening * old_weight + (1 - dampening) * new_weight

        # Normalize weights to sum to 1
        total_weight = sum(self.detector_weights.values())
        for detector in self.detector_weights:
            self.detector_weights[detector] /= total_weight

        logger.info(f"Weights adjusted from {len(list(self.performance_tracker['labeled_predictions']))} labeled samples")
        logger.info(f"  New weights: {self.detector_weights}")
        logger.info(f"  F1 scores: {f1_scores}")

    def provide_feedback(self, ground_truth_class: str):
        """
        Provide supervised feedback for weight adjustment and calibration.

        This is the ONLY way to properly adjust weights - agreement-based
        adjustment is methodologically flawed as it measures redundancy, not accuracy.
        """
        predictions = list(self.performance_tracker["predictions"])
        if not predictions:
            return

        # Get the most recent prediction
        last_record = predictions[-1]
        last_record["ground_truth"] = ground_truth_class

        # Store in labeled predictions
        self.performance_tracker["labeled_predictions"].append(last_record)

        # Update calibrator with new ground truth
        for detector_name, confidence in last_record.get("confidences", {}).items():
            self.calibrator.add_sample(detector_name, confidence, ground_truth_class)

        logger.info(f"Feedback recorded: {ground_truth_class}")

        # Adjust weights if we have enough labeled samples
        labeled_count = len(list(self.performance_tracker["labeled_predictions"]))
        if labeled_count >= 50 and labeled_count % 25 == 0:
            self._adjust_weights_from_accuracy(min_samples=30)

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for the ensemble."""
        metrics = self._compute_detector_accuracy()

        stats = {
            "total_predictions": len(list(self.performance_tracker["predictions"])),
            "labeled_predictions": len(list(self.performance_tracker["labeled_predictions"])),
            "current_weights": dict(self.detector_weights),
            "initial_weights": dict(self._initial_weights),
            "agreement_matrix": {},
            "detector_metrics": metrics,
            "calibration_status": {
                det: self.calibrator.is_calibrated.get(det, False)
                for det in self.detector_weights.keys()
            }
        }

        for key, counts in self.performance_tracker["agreements"].items():
            total = counts["agree"] + counts["disagree"]
            if total > 0:
                stats["agreement_matrix"][key] = {
                    "agreement_rate": counts["agree"] / total,
                    "total_comparisons": total,
                    "note": "Agreement measures redundancy, not accuracy"
                }

        return stats

    def reset_weights(self):
        """Reset weights to initial values."""
        self.detector_weights = dict(self._initial_weights)
        logger.info(f"Weights reset to initial values: {self.detector_weights}")

    def save_models(self):
        """Save trained models with metadata."""
        try:
            metadata = {
                "version": MODEL_VERSION,
                "timestamp": datetime.utcnow().isoformat(),
                "sigma": self.settings.detector_sigma,
                "model_name": self.settings.model_name,
                "tools_trained": list(self.semantic_detector.prototypes.keys()),
                "classification_type": "binary",
                "maml_enabled": self.maml_detector is not None,
                "detector_weights": dict(self.detector_weights)
            }

            semantic_state = self.semantic_detector.save_state()
            semantic_state["metadata"] = metadata
            torch.save(semantic_state, self.settings.semantic_model_path)

            stat_state = self.stat_detector.save_state()
            stat_state["metadata"] = metadata
            torch.save(stat_state, self.settings.statistical_model_path)

            if self.maml_detector:
                maml_state = self.maml_detector.save_state()
                maml_state["metadata"] = metadata
                torch.save(maml_state, self.settings.maml_model_path)
                logger.info("MAML model saved")

            logger.info(f"Models saved (version {MODEL_VERSION})")
            logger.info(f"   Tools: {metadata['tools_trained']}")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")

    def load_models(self) -> bool:
        """Load pre-trained models."""
        loaded = False

        if os.path.exists(self.settings.semantic_model_path):
            try:
                state = torch.load(
                    self.settings.semantic_model_path,
                    map_location=torch.device('cpu'),
                    weights_only=False
                )
                self.semantic_detector.load_state(state)
                metadata = state.get("metadata", {})
                logger.info(f"Semantic Model loaded (version {metadata.get('version', 'unknown')})")

                # Restore saved weights if available
                if "detector_weights" in metadata:
                    self.detector_weights = metadata["detector_weights"]
                    logger.info(f"  Restored weights: {self.detector_weights}")

                loaded = True
            except Exception as e:
                logger.error(f"Failed to load semantic model: {e}")

        if os.path.exists(self.settings.statistical_model_path):
            try:
                state = torch.load(
                    self.settings.statistical_model_path,
                    map_location=torch.device('cpu'),
                    weights_only=False
                )
                self.stat_detector.load_state(state)
                logger.info("Statistical Model loaded")
                loaded = True
            except Exception as e:
                logger.error(f"Failed to load statistical model: {e}")

        if self.maml_detector and os.path.exists(self.settings.maml_model_path):
            try:
                state = torch.load(
                    self.settings.maml_model_path,
                    map_location=torch.device('cpu'),
                    weights_only=False
                )
                self.maml_detector.load_state(state)
                logger.info("MAML Model loaded")
                loaded = True
            except Exception as e:
                logger.error(f"Failed to load MAML model: {e}")

        return loaded

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded models."""
        info = {
            "version": MODEL_VERSION,
            "classification_system": "binary (benign vs attack)",
            "ensemble": {
                "mode": "dynamic_weighted_voting",
                "calibration": "platt_scaling",
                "weights": dict(self.detector_weights),
                "initial_weights": dict(self._initial_weights),
                "total_predictions": len(list(self.performance_tracker["predictions"])),
                "labeled_predictions": len(list(self.performance_tracker["labeled_predictions"]))
            },
            "semantic_detector": {
                "tools": list(self.semantic_detector.prototypes.keys()),
                "thresholds": {k: dict(v) for k, v in self.semantic_detector.thresholds.items()}
            },
            "statistical_detector": {
                "tools": list(self.stat_detector.class_stats.keys()),
                "method": "mahalanobis_with_pooled_covariance",
                "features": self.stat_detector.features,
                "margin_thresholds": dict(self.stat_detector.margin_thresholds)
            },
            "rule_detector": {
                "attack_patterns": len(self.rule_detector.compiled_attack_patterns)
            },
            "settings": {
                "sigma": self.settings.detector_sigma,
                "model_name": self.settings.model_name
            }
        }

        if self.maml_detector:
            info["maml_detector"] = {
                "enabled": True,
                "adapted_tools": list(self.maml_detector.adapted_models.keys()),
                "config": {
                    "meta_lr": self.maml_detector.config.meta_lr,
                    "inner_lr": self.maml_detector.config.inner_lr,
                    "adaptation_steps": self.maml_detector.config.adaptation_steps,
                    "ways": self.maml_detector.config.ways
                }
            }
        else:
            info["maml_detector"] = {"enabled": False}

        return info

    @property
    def prototypes(self):
        """Expose semantic prototypes for checking initialization status."""
        return self.semantic_detector.prototypes


# Backwards compatibility alias
MultiClassMCPDetector = BinaryMCPDetector
