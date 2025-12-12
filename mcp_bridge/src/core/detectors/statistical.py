import math
import numpy as np
import logging
import re
from collections import Counter
from scipy import stats as scipy_stats
from typing import List, Optional, Dict, Any, Tuple
from .base import BaseDetector, DetectionResult, SecurityClass

logger = logging.getLogger(__name__)


class StatisticalFeatureDetector(BaseDetector):
    """
    Binary statistical detector using rich feature extraction and Mahalanobis distance.

    Classification:
    - BENIGN: Requests matching benign statistical profile
    - ATTACK: Requests matching attack profile or statistically anomalous

    Features (all normalized to comparable scales):
    - Log Length: Log-transformed character count
    - Entropy: Shannon entropy (randomness indicator)
    - Special Character Ratio: Non-alphanumeric characters
    - Digit Ratio: Numeric characters
    - Suspicious Pattern Density: Attack pattern frequency
    - Alphabetic Ratio: Letter concentration
    - Uppercase Ratio: Capitalization patterns
    - Whitespace Ratio: Space distribution
    - Max Token Length Ratio: Longest continuous token (normalized)
    - URL Pattern Density: URL/path pattern density

    Uses Mahalanobis distance with pooled within-class covariance for proper
    binary classification with fail-safe behavior.

    References:
    - Hastie, T., Tibshirani, R., & Friedman, J. (2009). The Elements of Statistical Learning.
    - McLachlan, G. J. (2004). Discriminant Analysis and Statistical Pattern Recognition.
    """

    # Random seed for reproducibility
    RANDOM_SEED = 42

    def __init__(self, sigma: float = 3.0, confidence_level: float = 0.997):
        """
        Initialize statistical detector.

        Args:
            sigma: Number of standard deviations for threshold (default 3.0 for 99.7%)
            confidence_level: Confidence level for chi-square threshold (default 0.997)
        """
        np.random.seed(self.RANDOM_SEED)

        self.sigma = sigma
        self.confidence_level = confidence_level

        # Binary statistics: {tool_name: {"benign": {...}, "attack": {...}}}
        self.class_stats: Dict[str, Dict[str, Any]] = {}

        # Pooled covariance per tool for proper Mahalanobis distance
        self.pooled_stats: Dict[str, Dict[str, Any]] = {}

        # Feature normalization parameters per tool
        self.normalization_params: Dict[str, Dict[str, np.ndarray]] = {}

        # Data-driven margin thresholds per tool
        self.margin_thresholds: Dict[str, float] = {}

        # Empirical anomaly thresholds (non-parametric, from training data)
        # These replace the chi-square assumption when available
        self.empirical_thresholds: Dict[str, Dict[str, float]] = {}

        # Per-class covariances for QDA mode (handles heteroscedasticity)
        self.per_class_inv_cov: Dict[str, Dict[str, np.ndarray]] = {}

        # Use QDA (separate covariances) vs LDA (pooled covariance)
        self.use_qda: bool = False  # Set during training based on homoscedasticity test

        # Feature names for extraction
        self.features = [
            "log_length", "entropy", "special_ratio", "digit_ratio",
            "suspicious_density", "alpha_ratio", "upper_ratio",
            "whitespace_ratio", "max_token_ratio", "url_pattern_density"
        ]
        self.n_features = len(self.features)

        # Suspicious patterns for density calculation
        self.suspicious_patterns = [
            r'\.\./', r'\.\.[/\\]', r'%2e%2e',  # Traversal
            r'[;&|`$]', r'\$\(', r'`',  # Command injection
            r"'|--|\bunion\b|\bselect\b", r'\bor\b.*=.*\bor\b',  # SQL
            r'/etc/', r'/proc/', r'C:\\Windows',  # System paths
            r'admin', r'root', r'password', r'secret',  # Sensitive keywords
        ]
        self.suspicious_regex = [re.compile(p, re.IGNORECASE) for p in self.suspicious_patterns]

    def _compute_chi2_threshold(self, alpha: float = None) -> float:
        """
        Compute chi-square threshold for anomaly detection.

        For Mahalanobis distance with n features, D^2 follows chi-square(n) distribution
        under the null hypothesis that the sample comes from the fitted distribution.

        NOTE: This assumes multivariate normality which may not hold for security data.
        Use empirical thresholds (from _compute_empirical_thresholds) when available.

        Args:
            alpha: Significance level (default: 1 - confidence_level)

        Returns:
            Chi-square critical value
        """
        if alpha is None:
            alpha = 1 - self.confidence_level
        return scipy_stats.chi2.ppf(1 - alpha, df=self.n_features)

    def _compute_empirical_thresholds(
        self,
        tool_name: str,
        stats_benign: Optional[Dict],
        stats_attack: Optional[Dict],
        inv_cov: np.ndarray
    ) -> Dict[str, float]:
        """
        Compute empirical (non-parametric) thresholds from training data.

        This avoids the Gaussian assumption of chi-square thresholds by using
        actual percentiles from the training distribution.

        Returns:
            Dict with 'benign_p95', 'benign_p99', 'attack_p05', 'anomaly' thresholds
        """
        thresholds = {
            "benign_p95": float('inf'),
            "benign_p99": float('inf'),
            "attack_p05": 0.0,
            "anomaly": float('inf')
        }

        # Compute distances for benign samples
        if stats_benign and "feature_matrix" in stats_benign:
            benign_dists = []
            for features in stats_benign["feature_matrix"]:
                dist = self._mahalanobis_distance(features, stats_benign["mean"], inv_cov)
                benign_dists.append(dist)

            if benign_dists:
                thresholds["benign_p95"] = float(np.percentile(benign_dists, 95))
                thresholds["benign_p99"] = float(np.percentile(benign_dists, 99))
                thresholds["anomaly"] = float(np.percentile(benign_dists, 99.5))

        # Compute distances for attack samples
        if stats_attack and "feature_matrix" in stats_attack:
            attack_dists = []
            for features in stats_attack["feature_matrix"]:
                dist = self._mahalanobis_distance(features, stats_attack["mean"], inv_cov)
                attack_dists.append(dist)

            if attack_dists:
                thresholds["attack_p05"] = float(np.percentile(attack_dists, 5))
                # Update anomaly threshold to be max of both distributions
                attack_max = float(np.percentile(attack_dists, 99.5))
                thresholds["anomaly"] = max(thresholds["anomaly"], attack_max)

        logger.info(f"  Empirical thresholds: benign_p95={thresholds['benign_p95']:.2f}, "
                    f"anomaly={thresholds['anomaly']:.2f}")

        return thresholds

    def _test_homoscedasticity(
        self,
        stats_benign: Optional[Dict],
        stats_attack: Optional[Dict]
    ) -> Tuple[bool, float]:
        """
        Test whether class covariances are approximately equal (homoscedasticity).

        Uses a simplified Box's M test approximation. If variances differ significantly,
        QDA (separate covariances) should be used instead of LDA (pooled covariance).

        Returns:
            Tuple of (is_homoscedastic, ratio) where ratio is max/min eigenvalue ratio
        """
        if stats_benign is None or stats_attack is None:
            return True, 1.0  # Can't test with single class

        S1 = stats_benign["cov"]
        S2 = stats_attack["cov"]

        # Compare eigenvalue spectra as a simple homoscedasticity test
        eig1 = np.linalg.eigvalsh(S1)
        eig2 = np.linalg.eigvalsh(S2)

        # Ratio of condition numbers (simplified)
        cond1 = max(eig1) / (min(eig1) + 1e-10)
        cond2 = max(eig2) / (min(eig2) + 1e-10)

        ratio = max(cond1, cond2) / (min(cond1, cond2) + 1e-10)

        # Also check trace ratio (total variance)
        trace_ratio = np.trace(S1) / (np.trace(S2) + 1e-10)
        if trace_ratio < 1:
            trace_ratio = 1 / trace_ratio

        # Heuristic: if ratio > 3 or trace_ratio > 2, likely heteroscedastic
        is_homoscedastic = ratio < 3.0 and trace_ratio < 2.0

        logger.info(f"  Homoscedasticity test: ratio={ratio:.2f}, trace_ratio={trace_ratio:.2f}, "
                    f"homoscedastic={is_homoscedastic}")

        return is_homoscedastic, ratio

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the text in bits using log2.

        Uses collections.Counter for O(n) efficiency instead of O(n*m).
        """
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        # Use log2 directly for entropy in bits
        return -sum((count / length) * math.log2(count / length)
                    for count in counts.values() if count > 0)

    def _extract_raw_features(self, text: str) -> np.ndarray:
        """Extract raw statistical features from payload text (before normalization)."""
        length = len(text)
        if length == 0:
            return np.zeros(self.n_features, dtype=np.float32)

        # Basic character statistics
        specials = sum(1 for c in text if not c.isalnum() and not c.isspace())
        digits = sum(1 for c in text if c.isdigit())
        alpha = sum(1 for c in text if c.isalpha())
        upper = sum(1 for c in text if c.isupper())
        whitespace = sum(1 for c in text if c.isspace())

        # Suspicious pattern density (matches per character)
        suspicious_count = sum(
            len(regex.findall(text)) for regex in self.suspicious_regex
        )

        # Token analysis (split by non-alphanumeric)
        tokens = re.findall(r'[a-zA-Z0-9]+', text)
        max_token = max((len(t) for t in tokens), default=0)

        # URL/path patterns
        url_patterns = len(re.findall(r'(?:https?://|file://|ftp://|/[a-zA-Z0-9_/]+|[A-Z]:\\)', text))

        return np.array([
            math.log1p(length),              # Log-transform length to reduce scale dominance
            self._calculate_entropy(text),   # Already bounded ~0-8 for ASCII
            specials / length,               # 0-1
            digits / length,                 # 0-1
            suspicious_count / (length + 1), # ~0-1 (normalized)
            alpha / length,                  # 0-1
            upper / (alpha + 1e-9),          # 0-1 (ratio of uppercase to all letters)
            whitespace / length,             # 0-1
            max_token / (length + 1),        # 0-1 (normalized max token)
            url_patterns / (length / 10 + 1) # ~0-1 (URL patterns per 10 chars)
        ], dtype=np.float32)

    def _normalize_features(self, features: np.ndarray, tool_name: str) -> np.ndarray:
        """Apply z-score normalization using stored parameters."""
        if tool_name not in self.normalization_params:
            return features

        params = self.normalization_params[tool_name]
        mean = params["mean"]
        std = params["std"]

        # Z-score normalization with numerical stability
        return (features - mean) / (std + 1e-8)

    def _extract_features(self, text: str, tool_name: Optional[str] = None) -> np.ndarray:
        """Extract and normalize features from payload text."""
        raw_features = self._extract_raw_features(text)

        if tool_name and tool_name in self.normalization_params:
            return self._normalize_features(raw_features, tool_name)

        return raw_features

    def _compute_normalization_params(self, all_samples: List[str]) -> Dict[str, np.ndarray]:
        """Compute normalization parameters from all training samples."""
        if not all_samples:
            return {"mean": np.zeros(self.n_features), "std": np.ones(self.n_features)}

        feature_matrix = np.array([self._extract_raw_features(s) for s in all_samples])

        return {
            "mean": np.mean(feature_matrix, axis=0),
            "std": np.std(feature_matrix, axis=0)
        }

    def _compute_class_stats(self, samples: List[str], tool_name: str) -> Optional[Dict[str, Any]]:
        """Compute mean and covariance for a class using normalized features."""
        if not samples or len(samples) < 2:
            return None

        # Extract normalized features
        feature_matrix = np.array([
            self._extract_features(s, tool_name) for s in samples
        ])

        mean = np.mean(feature_matrix, axis=0)

        # Compute covariance with regularization
        cov = np.cov(feature_matrix, rowvar=False)
        if cov.ndim == 0:  # Handle single feature edge case
            cov = np.array([[cov]])

        # Add regularization to prevent singular covariance
        cov = cov + np.eye(self.n_features) * 1e-6

        return {
            "mean": mean,
            "cov": cov,
            "feature_matrix": feature_matrix,  # Keep for pooled covariance
            "samples": len(samples)
        }

    def _compute_pooled_covariance(
        self,
        stats_benign: Optional[Dict],
        stats_attack: Optional[Dict]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Compute pooled within-class covariance matrix.

        This ensures Mahalanobis distances to different class centroids are
        computed on the same scale, making them directly comparable.

        Formula: S_pooled = ((n1-1)*S1 + (n2-1)*S2) / (n1 + n2 - 2)

        Returns:
            Tuple of (pooled_cov, pooled_inv_cov)
        """
        if stats_benign is None and stats_attack is None:
            # Fallback to identity
            return np.eye(self.n_features), np.eye(self.n_features)

        if stats_attack is None:
            # Only benign available
            cov = stats_benign["cov"]
            return cov, np.linalg.inv(cov)

        if stats_benign is None:
            # Only attack available (unusual case)
            cov = stats_attack["cov"]
            return cov, np.linalg.inv(cov)

        # Both classes available - compute pooled covariance
        n1 = stats_benign["samples"]
        n2 = stats_attack["samples"]
        S1 = stats_benign["cov"]
        S2 = stats_attack["cov"]

        # Pooled within-class covariance (LDA formula)
        pooled_cov = ((n1 - 1) * S1 + (n2 - 1) * S2) / (n1 + n2 - 2)

        # Add regularization
        pooled_cov = pooled_cov + np.eye(self.n_features) * 1e-6

        try:
            pooled_inv_cov = np.linalg.inv(pooled_cov)
        except np.linalg.LinAlgError:
            # Fallback to pseudo-inverse if singular
            pooled_inv_cov = np.linalg.pinv(pooled_cov)

        return pooled_cov, pooled_inv_cov

    def _compute_data_driven_margin(
        self,
        stats_benign: Optional[Dict],
        stats_attack: Optional[Dict],
        pooled_inv_cov: np.ndarray
    ) -> float:
        """
        Compute optimal margin threshold from training data.

        Uses the distribution of margins observed in training to set a
        threshold that optimizes separation between classes.

        Returns:
            Optimal margin threshold (default 0.15 if insufficient data)
        """
        DEFAULT_MARGIN = 0.15

        if stats_benign is None or stats_attack is None:
            return DEFAULT_MARGIN

        benign_mean = stats_benign["mean"]
        attack_mean = stats_attack["mean"]

        # Compute margins for all training samples
        margins = []

        # Benign samples should have positive margins
        if "feature_matrix" in stats_benign:
            for features in stats_benign["feature_matrix"]:
                d_benign = self._mahalanobis_distance(features, benign_mean, pooled_inv_cov)
                d_attack = self._mahalanobis_distance(features, attack_mean, pooled_inv_cov)
                margin = (d_attack - d_benign) / (d_attack + d_benign + 1e-9)
                margins.append(("benign", margin))

        # Attack samples should have negative margins
        if "feature_matrix" in stats_attack:
            for features in stats_attack["feature_matrix"]:
                d_benign = self._mahalanobis_distance(features, benign_mean, pooled_inv_cov)
                d_attack = self._mahalanobis_distance(features, attack_mean, pooled_inv_cov)
                margin = (d_attack - d_benign) / (d_attack + d_benign + 1e-9)
                margins.append(("attack", margin))

        if len(margins) < 10:
            return DEFAULT_MARGIN

        # Find threshold that best separates classes
        benign_margins = [m for label, m in margins if label == "benign"]
        attack_margins = [m for label, m in margins if label == "attack"]

        if not benign_margins or not attack_margins:
            return DEFAULT_MARGIN

        # Use the midpoint between class margin distributions
        # with bias toward security (lower threshold = more strict)
        benign_lower = np.percentile(benign_margins, 10)  # 10th percentile of benign
        attack_upper = np.percentile(attack_margins, 90)  # 90th percentile of attack

        # Optimal threshold is between these, biased toward security
        optimal_margin = (benign_lower + attack_upper) / 2

        # Clamp to reasonable range
        return float(np.clip(optimal_margin, 0.05, 0.30))

    def fit(self, tool_name: str, benign_samples: List[str],
            attack_samples: Optional[List[str]] = None):
        """
        Fit binary statistical model using Mahalanobis distance with pooled covariance.

        Args:
            tool_name: Tool identifier
            benign_samples: Known safe requests
            attack_samples: Known attack patterns (all attack types merged)
        """
        if not benign_samples:
            logger.warning(f"No benign samples for {tool_name}, skipping statistical training")
            return

        logger.info(f"Training binary statistical model for {tool_name}...")

        # Step 1: Compute normalization parameters from ALL samples
        all_samples = list(benign_samples)
        if attack_samples:
            all_samples.extend(attack_samples)

        self.normalization_params[tool_name] = self._compute_normalization_params(all_samples)
        logger.info(f"  Computed normalization params from {len(all_samples)} samples")

        # Step 2: Compute per-class statistics with normalized features
        self.class_stats[tool_name] = {}

        stats_benign = self._compute_class_stats(benign_samples, tool_name)
        if stats_benign:
            self.class_stats[tool_name][SecurityClass.BENIGN.value] = stats_benign
            logger.info(f"  Benign: {stats_benign['samples']} samples")

        stats_attack = None
        if attack_samples:
            stats_attack = self._compute_class_stats(attack_samples, tool_name)
            if stats_attack:
                self.class_stats[tool_name][SecurityClass.ATTACK.value] = stats_attack
                logger.info(f"  Attack: {stats_attack['samples']} samples")

        # Step 3: Test homoscedasticity to decide LDA vs QDA
        is_homoscedastic, cov_ratio = self._test_homoscedasticity(stats_benign, stats_attack)

        # Step 4: Compute covariance matrices
        pooled_cov, pooled_inv_cov = self._compute_pooled_covariance(stats_benign, stats_attack)
        self.pooled_stats[tool_name] = {
            "cov": pooled_cov,
            "inv_cov": pooled_inv_cov
        }

        # Store per-class inverse covariances for QDA mode
        self.per_class_inv_cov[tool_name] = {}
        if stats_benign:
            try:
                self.per_class_inv_cov[tool_name][SecurityClass.BENIGN.value] = np.linalg.inv(
                    stats_benign["cov"]
                )
            except np.linalg.LinAlgError:
                self.per_class_inv_cov[tool_name][SecurityClass.BENIGN.value] = np.linalg.pinv(
                    stats_benign["cov"]
                )
        if stats_attack:
            try:
                self.per_class_inv_cov[tool_name][SecurityClass.ATTACK.value] = np.linalg.inv(
                    stats_attack["cov"]
                )
            except np.linalg.LinAlgError:
                self.per_class_inv_cov[tool_name][SecurityClass.ATTACK.value] = np.linalg.pinv(
                    stats_attack["cov"]
                )

        # Use QDA if heteroscedastic (different class covariances)
        self.use_qda = not is_homoscedastic
        if self.use_qda:
            logger.info(f"  Using QDA mode (heteroscedastic classes, ratio={cov_ratio:.2f})")
        else:
            logger.info(f"  Using LDA mode (pooled covariance)")

        # Step 5: Compute empirical thresholds (non-parametric, avoids Gaussian assumption)
        self.empirical_thresholds[tool_name] = self._compute_empirical_thresholds(
            tool_name, stats_benign, stats_attack, pooled_inv_cov
        )

        # Step 6: Compute data-driven margin threshold
        self.margin_thresholds[tool_name] = self._compute_data_driven_margin(
            stats_benign, stats_attack, pooled_inv_cov
        )
        logger.info(f"  Margin threshold: {self.margin_thresholds[tool_name]:.3f}")

        # Clean up feature matrices to save memory
        for class_stats in self.class_stats[tool_name].values():
            if "feature_matrix" in class_stats:
                del class_stats["feature_matrix"]

        logger.info(f"Statistical model fitted for {tool_name} with {len(self.class_stats[tool_name])} classes")

    def _mahalanobis_distance(self, x: np.ndarray, mean: np.ndarray, inv_cov: np.ndarray) -> float:
        """
        Compute Mahalanobis distance between x and distribution.

        D(x) = sqrt((x - μ)^T Σ^{-1} (x - μ))
        """
        diff = x - mean
        return float(np.sqrt(np.dot(np.dot(diff, inv_cov), diff)))

    def predict(self, payload: str, tool_name: Optional[str] = None) -> Optional[DetectionResult]:
        """
        Binary statistical classification using Mahalanobis distance.

        Strategy:
        1. Extract and normalize features from payload
        2. Compute Mahalanobis distance to class centroids
           - LDA mode: Use pooled covariance (assumes homoscedasticity)
           - QDA mode: Use per-class covariances (handles heteroscedasticity)
        3. Use empirical thresholds (non-parametric) when available, fallback to chi-square
        4. Classify based on relative distances with data-driven margin threshold
        5. Anomalous samples (far from both) are treated as attacks (fail-safe)
        """
        if not tool_name or tool_name not in self.class_stats:
            return None

        if not self.class_stats[tool_name]:
            return None

        # Extract normalized features
        features = self._extract_features(payload, tool_name)

        # Get inverse covariance matrices
        if tool_name not in self.pooled_stats:
            return None

        pooled_inv_cov = self.pooled_stats[tool_name]["inv_cov"]
        per_class_inv = self.per_class_inv_cov.get(tool_name, {})

        # Compute distances to class centroids
        # Use per-class covariance (QDA) or pooled covariance (LDA) based on training
        distances = {}
        for class_name, stats in self.class_stats[tool_name].items():
            if self.use_qda and class_name in per_class_inv:
                # QDA mode: use class-specific covariance
                inv_cov = per_class_inv[class_name]
            else:
                # LDA mode: use pooled covariance
                inv_cov = pooled_inv_cov
            dist = self._mahalanobis_distance(features, stats["mean"], inv_cov)
            distances[class_name] = dist

        # Get thresholds - prefer empirical (non-parametric) over chi-square (Gaussian assumption)
        empirical = self.empirical_thresholds.get(tool_name, {})
        if empirical:
            # Use empirical threshold (avoids Gaussian assumption)
            anomaly_threshold = empirical.get("anomaly", float('inf'))
            benign_threshold = empirical.get("benign_p99", float('inf'))
            threshold_type = "empirical"
        else:
            # Fallback to chi-square (assumes Gaussian - may not be accurate)
            chi2_threshold = self._compute_chi2_threshold()
            anomaly_threshold = chi2_threshold * 1.5
            benign_threshold = chi2_threshold
            threshold_type = "chi2"

        # Get data-driven margin threshold
        margin_threshold = self.margin_thresholds.get(tool_name, 0.15)

        metadata = {
            "distances": {k: float(v) for k, v in distances.items()},
            "features": features.tolist(),
            "detector": "statistical",
            "threshold_type": threshold_type,
            "anomaly_threshold": float(anomaly_threshold),
            "margin_threshold": margin_threshold,
            "mode": "QDA" if self.use_qda else "LDA"
        }

        benign_dist = distances.get(SecurityClass.BENIGN.value)
        attack_dist = distances.get(SecurityClass.ATTACK.value)

        # Case 1: Only benign statistics available
        if attack_dist is None:
            if benign_dist is None:
                return None

            # Use empirical/chi2 threshold for anomaly detection
            if benign_dist > anomaly_threshold:
                confidence = min(0.95, 0.5 + benign_dist / (anomaly_threshold * 2))
                return DetectionResult.attack(
                    confidence=confidence,
                    reason=f"Statistical anomaly (dist={benign_dist:.1f} > threshold={anomaly_threshold:.1f})",
                    metadata=metadata
                )
            elif benign_dist > benign_threshold:
                confidence = 0.5 + 0.3 * (benign_dist - benign_threshold) / (anomaly_threshold - benign_threshold + 1e-9)
                return DetectionResult.attack(
                    confidence=confidence,
                    reason=f"Beyond benign boundary (dist={benign_dist:.1f} > {benign_threshold:.1f})",
                    metadata=metadata
                )
            else:
                confidence = max(0.5, min(0.95, 1.0 - benign_dist / benign_threshold))
                return DetectionResult.benign(
                    confidence=confidence,
                    reason=f"Within benign distribution (dist={benign_dist:.1f})",
                    metadata=metadata
                )

        # Case 2: Both classes available - relative distance classification
        # Check for anomaly (far from both classes)
        if benign_dist > anomaly_threshold and attack_dist > anomaly_threshold:
            confidence = min(0.95, 0.6 + min(benign_dist, attack_dist) / (anomaly_threshold * 2))
            return DetectionResult.attack(
                confidence=confidence,
                reason=f"Anomaly: far from both classes (benign={benign_dist:.1f}, attack={attack_dist:.1f})",
                metadata=metadata
            )

        # Compute relative margin
        margin = (attack_dist - benign_dist) / (attack_dist + benign_dist + 1e-9)
        metadata["margin"] = float(margin)

        # Positive margin = closer to benign, negative = closer to attack
        if margin > margin_threshold:
            # Clearly closer to benign
            confidence = max(0.5, min(0.95, 0.6 + margin))
            return DetectionResult.benign(
                confidence=confidence,
                reason=f"Closer to benign distribution (margin={margin:.2%} > {margin_threshold:.2%})",
                metadata=metadata
            )
        elif margin < -margin_threshold:
            # Clearly closer to attack
            confidence = max(0.5, min(0.95, 0.6 + abs(margin)))
            return DetectionResult.attack(
                confidence=confidence,
                reason=f"Closer to attack distribution (margin={margin:.2%})",
                metadata=metadata
            )
        else:
            # Ambiguous - fail-safe to attack
            confidence = 0.5 + 0.2 * abs(margin) / margin_threshold
            return DetectionResult.attack(
                confidence=confidence,
                reason=f"Ambiguous, fail-safe to attack (margin={margin:.2%})",
                metadata=metadata
            )

    def save_state(self) -> Dict[str, Any]:
        """Save model state for persistence."""
        serializable_stats = {}
        for tool_name, classes in self.class_stats.items():
            serializable_stats[tool_name] = {}
            for class_name, stats in classes.items():
                serializable_stats[tool_name][class_name] = {
                    "mean": stats["mean"].tolist(),
                    "cov": stats["cov"].tolist(),
                    "samples": stats["samples"]
                }

        serializable_pooled = {}
        for tool_name, stats in self.pooled_stats.items():
            serializable_pooled[tool_name] = {
                "cov": stats["cov"].tolist(),
                "inv_cov": stats["inv_cov"].tolist()
            }

        serializable_norm = {}
        for tool_name, params in self.normalization_params.items():
            serializable_norm[tool_name] = {
                "mean": params["mean"].tolist(),
                "std": params["std"].tolist()
            }

        # Serialize per-class inverse covariances for QDA
        serializable_per_class_inv = {}
        for tool_name, classes in self.per_class_inv_cov.items():
            serializable_per_class_inv[tool_name] = {
                class_name: inv_cov.tolist()
                for class_name, inv_cov in classes.items()
            }

        return {
            "class_stats": serializable_stats,
            "pooled_stats": serializable_pooled,
            "normalization_params": serializable_norm,
            "margin_thresholds": self.margin_thresholds,
            "empirical_thresholds": self.empirical_thresholds,
            "per_class_inv_cov": serializable_per_class_inv,
            "use_qda": self.use_qda,
            "features": self.features,
            "confidence_level": self.confidence_level,
            "version": "4.0",  # Bumped version for QDA and empirical thresholds
            "type": "binary"
        }

    def load_state(self, state: Dict[str, Any]):
        """Load model state from persistence."""
        # Load confidence level
        self.confidence_level = state.get("confidence_level", 0.997)

        # Load normalization parameters
        self.normalization_params = {}
        for tool_name, params in state.get("normalization_params", {}).items():
            self.normalization_params[tool_name] = {
                "mean": np.array(params["mean"], dtype=np.float32),
                "std": np.array(params["std"], dtype=np.float32)
            }

        # Load class statistics
        serialized_stats = state.get("class_stats", {})
        self.class_stats = {}
        for tool_name, classes in serialized_stats.items():
            self.class_stats[tool_name] = {}
            for class_name, stats in classes.items():
                mean = np.array(stats["mean"], dtype=np.float32)
                cov = np.array(stats["cov"], dtype=np.float32)
                self.class_stats[tool_name][class_name] = {
                    "mean": mean,
                    "cov": cov,
                    "samples": stats["samples"]
                }

        # Load pooled statistics
        self.pooled_stats = {}
        for tool_name, stats in state.get("pooled_stats", {}).items():
            cov = np.array(stats["cov"], dtype=np.float32)
            inv_cov = np.array(stats["inv_cov"], dtype=np.float32)
            self.pooled_stats[tool_name] = {
                "cov": cov,
                "inv_cov": inv_cov
            }

        # For backward compatibility: compute pooled stats if not present
        if not self.pooled_stats:
            for tool_name, classes in self.class_stats.items():
                benign_stats = classes.get(SecurityClass.BENIGN.value)
                attack_stats = classes.get(SecurityClass.ATTACK.value)
                pooled_cov, pooled_inv_cov = self._compute_pooled_covariance(
                    benign_stats, attack_stats
                )
                self.pooled_stats[tool_name] = {
                    "cov": pooled_cov,
                    "inv_cov": pooled_inv_cov
                }

        # Load per-class inverse covariances for QDA
        self.per_class_inv_cov = {}
        for tool_name, classes in state.get("per_class_inv_cov", {}).items():
            self.per_class_inv_cov[tool_name] = {
                class_name: np.array(inv_cov, dtype=np.float32)
                for class_name, inv_cov in classes.items()
            }

        # For backward compatibility: compute per-class inv cov if not present
        if not self.per_class_inv_cov:
            for tool_name, classes in self.class_stats.items():
                self.per_class_inv_cov[tool_name] = {}
                for class_name, stats in classes.items():
                    try:
                        self.per_class_inv_cov[tool_name][class_name] = np.linalg.inv(stats["cov"])
                    except np.linalg.LinAlgError:
                        self.per_class_inv_cov[tool_name][class_name] = np.linalg.pinv(stats["cov"])

        # Load QDA mode flag
        self.use_qda = state.get("use_qda", False)

        # Load margin thresholds
        self.margin_thresholds = state.get("margin_thresholds", {})

        # Load empirical thresholds
        self.empirical_thresholds = state.get("empirical_thresholds", {})

        # For backward compatibility: use default margins if not present
        for tool_name in self.class_stats:
            if tool_name not in self.margin_thresholds:
                self.margin_thresholds[tool_name] = 0.15
