import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel
import numpy as np
import re
import logging
from typing import List, Optional, Dict, Any, Tuple
from .base import BaseDetector, DetectionResult, SecurityClass

logger = logging.getLogger(__name__)

# Random seed for reproducibility
RANDOM_SEED = 42
torch.manual_seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# Security-relevant patterns for feature augmentation
ATTACK_PATTERNS = [
    r'\.\./',           # Path traversal
    r'\.\.\\',          # Windows path traversal
    r'%2[eE]%2[eE]',    # URL-encoded ..
    r'/etc/',           # Linux system files
    r'/proc/',          # Linux proc filesystem
    r'C:\\Windows',     # Windows system
    r'\$\(',            # Command substitution
    r'`[^`]+`',         # Backtick execution
    r'[;&|]',           # Command chaining
    r'php://',          # PHP wrappers
    r'file://',         # File protocol
    r'\x00',            # Null byte
    r'\.env',           # Environment files
    r'secret',          # Secrets directory
    r'credential',      # Credentials
    r'password',        # Password files
    r'api.?key',        # API keys
    r'\.pem$',          # PEM certificates
    r'id_rsa',          # SSH keys
    r'/root/',          # Root directory
    r'\.ssh/',          # SSH directory
]


class SemanticDetector(BaseDetector):
    """
    Deep Learning approach using prototypical learning with DistilBERT embeddings.

    Binary Classification Strategy:
    - Computes distance to BENIGN and ATTACK prototypes
    - Uses relative distance with DATA-DRIVEN margin-based decision boundary
    - Requests closer to ATTACK prototype are blocked
    - Out-of-distribution samples (far from both) are treated as attacks (fail-safe)

    Key improvements:
    - Data-driven margin thresholds computed from training distributions
    - Tool-specific thresholds for better calibration
    - Explicit separation of security features from semantic features
    """

    # Default margin values (used when insufficient training data)
    DEFAULT_MARGIN_RATIO = 0.10
    DEFAULT_ANOMALY_MULTIPLIER = 1.5

    def __init__(self, model_name: str, sigma: float = 3.0):
        # Set random seed for reproducibility
        torch.manual_seed(RANDOM_SEED)
        np.random.seed(RANDOM_SEED)

        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.eval()
        self.sigma = sigma

        self.prototypes = {}  # {tool_name: {"benign": tensor, "attack": tensor}}
        self.thresholds = {}  # {tool_name: {"boundary": float, "anomaly": float, "margin": float}}
        self.class_stats = {}  # {tool_name: {"benign": {...}, "attack": {...}}}

        # Store training embeddings for margin computation
        self._training_embeddings = {}  # {tool_name: {"benign": tensor, "attack": tensor}}

        logger.info(f"Loaded semantic model: {model_name}")

    def _extract_security_features(self, text_payload: str) -> np.ndarray:
        """
        Extract security-relevant features to augment embeddings.

        Note: These features overlap with rule-based detector patterns.
        This is intentional for the semantic detector to learn correlations,
        but ensemble diversity should be monitored.
        """
        features = []

        # Count attack pattern matches
        attack_score = sum(1 for p in ATTACK_PATTERNS if re.search(p, text_payload, re.IGNORECASE))
        features.append(min(attack_score / 5.0, 1.0))  # Normalize

        # Path depth (number of directory levels)
        path_depth = text_payload.count('/') + text_payload.count('\\')
        features.append(min(path_depth / 10.0, 1.0))

        # Special character density
        special_chars = sum(1 for c in text_payload if c in '$`|;&<>(){}[]')
        features.append(min(special_chars / 5.0, 1.0))

        # Has parent directory reference
        features.append(1.0 if '..' in text_payload else 0.0)

        # Has absolute path
        features.append(1.0 if (text_payload.startswith('/') or re.match(r'^[A-Za-z]:\\', text_payload)) else 0.0)

        # Payload length normalized
        features.append(min(len(text_payload) / 500.0, 1.0))

        return np.array(features, dtype=np.float32)

    def _get_embedding(self, text_payload: str) -> torch.Tensor:
        """Generate normalized embedding with security feature augmentation."""
        inputs = self.tokenizer(
            text_payload,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding=True
        )
        with torch.no_grad():
            outputs = self.model(**inputs)

        token_embeddings = outputs.last_hidden_state
        attention_mask = inputs['attention_mask'].unsqueeze(-1).expand(token_embeddings.size()).float()
        sum_embeddings = torch.sum(token_embeddings * attention_mask, 1)
        sum_mask = torch.clamp(attention_mask.sum(1), min=1e-9)
        mean_embedding = sum_embeddings / sum_mask

        # Augment with security features
        security_features = self._extract_security_features(text_payload)
        security_tensor = torch.tensor(security_features, dtype=mean_embedding.dtype).unsqueeze(0)

        # Concatenate and re-normalize
        augmented = torch.cat([mean_embedding, security_tensor], dim=1)
        return F.normalize(augmented, p=2, dim=1)

    def _compute_prototype(self, samples: List[str], tool_name: str, class_name: str) -> Optional[torch.Tensor]:
        """Compute prototype and statistics for a class."""
        if not samples:
            return None

        embeddings = torch.vstack([self._get_embedding(s) for s in samples])
        prototype = torch.mean(embeddings, dim=0, keepdim=True)
        self.prototypes[tool_name][class_name] = F.normalize(prototype, p=2, dim=1)

        # Store embeddings for margin computation
        if tool_name not in self._training_embeddings:
            self._training_embeddings[tool_name] = {}
        self._training_embeddings[tool_name][class_name] = embeddings

        # Compute intra-class statistics
        cosine_sims = F.cosine_similarity(embeddings, self.prototypes[tool_name][class_name])
        distances = (1.0 - cosine_sims).cpu().numpy()

        self.class_stats[tool_name][class_name] = {
            "mean": float(np.mean(distances)),
            "std": float(np.std(distances)),
            "max_dist": float(np.max(distances)),
            "min_dist": float(np.min(distances)),
            "percentile_90": float(np.percentile(distances, 90)),
            "percentile_10": float(np.percentile(distances, 10)),
            "n_samples": len(samples)
        }

        logger.info(f"  {class_name}: n={len(samples)}, mean_dist={np.mean(distances):.4f}, "
                    f"std={np.std(distances):.4f}, max={np.max(distances):.4f}")

        return embeddings

    def _compute_data_driven_margin(self, tool_name: str) -> float:
        """
        Compute optimal margin threshold from training data.

        Uses the distribution of margins observed in training to set a
        threshold that optimizes separation between classes.

        Returns:
            Optimal margin threshold (falls back to DEFAULT_MARGIN_RATIO if insufficient data)
        """
        if tool_name not in self._training_embeddings:
            return self.DEFAULT_MARGIN_RATIO

        embeddings = self._training_embeddings[tool_name]
        prototypes = self.prototypes[tool_name]

        if SecurityClass.BENIGN.value not in embeddings or SecurityClass.ATTACK.value not in embeddings:
            return self.DEFAULT_MARGIN_RATIO

        benign_emb = embeddings[SecurityClass.BENIGN.value]
        attack_emb = embeddings[SecurityClass.ATTACK.value]
        benign_proto = prototypes[SecurityClass.BENIGN.value]
        attack_proto = prototypes[SecurityClass.ATTACK.value]

        # Compute margins for all training samples
        margins = []

        # Benign samples - compute margin
        for emb in benign_emb:
            emb = emb.unsqueeze(0)
            d_benign = float(1.0 - F.cosine_similarity(emb, benign_proto).item())
            d_attack = float(1.0 - F.cosine_similarity(emb, attack_proto).item())
            margin = (d_attack - d_benign) / (d_attack + d_benign + 1e-9)
            margins.append(("benign", margin))

        # Attack samples - compute margin
        for emb in attack_emb:
            emb = emb.unsqueeze(0)
            d_benign = float(1.0 - F.cosine_similarity(emb, benign_proto).item())
            d_attack = float(1.0 - F.cosine_similarity(emb, attack_proto).item())
            margin = (d_attack - d_benign) / (d_attack + d_benign + 1e-9)
            margins.append(("attack", margin))

        if len(margins) < 10:
            return self.DEFAULT_MARGIN_RATIO

        # Separate margins by class
        benign_margins = [m for label, m in margins if label == "benign"]
        attack_margins = [m for label, m in margins if label == "attack"]

        if not benign_margins or not attack_margins:
            return self.DEFAULT_MARGIN_RATIO

        # Compute statistics
        benign_mean = np.mean(benign_margins)
        benign_std = np.std(benign_margins)
        attack_mean = np.mean(attack_margins)
        attack_std = np.std(attack_margins)

        # Find threshold that best separates classes
        # Use the point where class distributions overlap minimally
        benign_lower = np.percentile(benign_margins, 10)  # 10th percentile of benign (most attack-like benign)
        attack_upper = np.percentile(attack_margins, 90)  # 90th percentile of attack (most benign-like attack)

        # Optimal threshold is midpoint between class boundaries
        # This is more principled than arbitrary weights
        # If classes are well-separated, midpoint will be close to zero
        # If classes overlap, midpoint will be at the overlap region
        optimal_margin = (benign_lower + attack_upper) / 2.0

        # Apply security bias: if margin is positive (attack side), reduce by 20%
        # This provides fail-safe behavior without arbitrary 0.3/0.7 weights
        if optimal_margin > 0:
            optimal_margin *= 0.8  # Slightly stricter

        # Clamp to reasonable range
        optimal_margin = float(np.clip(optimal_margin, 0.03, 0.30))

        logger.info(f"  Data-driven margin: {optimal_margin:.4f} "
                    f"(benign_mean={benign_mean:.4f}, attack_mean={attack_mean:.4f})")

        return optimal_margin

    def _compute_decision_boundary(self, tool_name: str):
        """Compute decision boundary between benign and attack prototypes."""
        prototypes = self.prototypes[tool_name]

        if SecurityClass.BENIGN.value not in prototypes:
            return

        benign_stats = self.class_stats[tool_name].get(SecurityClass.BENIGN.value, {})

        # If we have attack samples, compute inter-prototype distance
        if SecurityClass.ATTACK.value in prototypes:
            p_benign = prototypes[SecurityClass.BENIGN.value]
            p_attack = prototypes[SecurityClass.ATTACK.value]
            inter_dist = float(1.0 - F.cosine_similarity(p_benign, p_attack).item())

            attack_stats = self.class_stats[tool_name].get(SecurityClass.ATTACK.value, {})

            # Use percentiles for more robust threshold estimation
            benign_p90 = benign_stats.get("percentile_90", benign_stats.get("max_dist", 0.1))
            attack_p90 = attack_stats.get("percentile_90", attack_stats.get("max_dist", 0.1))

            # Boundary threshold: robust estimate using percentiles
            boundary = min(
                (benign_p90 + attack_p90) / 2.0,
                inter_dist / 2.0
            )

            # Anomaly threshold: outside both class distributions
            anomaly = max(
                benign_stats.get("max_dist", 0.1),
                attack_stats.get("max_dist", 0.1)
            ) * self.DEFAULT_ANOMALY_MULTIPLIER

            # Compute data-driven margin
            margin = self._compute_data_driven_margin(tool_name)

            logger.info(f"  Inter-prototype distance: {inter_dist:.4f}")
            logger.info(f"  Decision boundary: {boundary:.4f}, Anomaly threshold: {anomaly:.4f}")
            logger.info(f"  Margin threshold: {margin:.4f}")

        else:
            # Only benign samples - use sigma rule for boundary
            boundary = benign_stats.get("mean", 0.0) + self.sigma * benign_stats.get("std", 0.1)
            anomaly = benign_stats.get("max_dist", 0.1) * self.DEFAULT_ANOMALY_MULTIPLIER
            margin = self.DEFAULT_MARGIN_RATIO

            logger.info(f"  Single-class boundary (sigma rule): {boundary:.4f}")

        self.thresholds[tool_name] = {
            "boundary": boundary,
            "anomaly": anomaly,
            "margin": margin
        }

    def fit(self, tool_name: str, benign_samples: List[str],
            attack_samples: Optional[List[str]] = None):
        """
        Train semantic prototypes for binary classification.

        Args:
            tool_name: Name of the tool being trained
            benign_samples: Known safe requests
            attack_samples: Known attack patterns (all attack types merged)
        """
        if not benign_samples:
            return

        logger.info(f"Training semantic prototypes for {tool_name}...")
        self.prototypes[tool_name] = {}
        self.thresholds[tool_name] = {}
        self.class_stats[tool_name] = {}
        self._training_embeddings[tool_name] = {}

        # Compute benign prototype
        self._compute_prototype(benign_samples, tool_name, SecurityClass.BENIGN.value)

        # Compute attack prototype if samples provided
        if attack_samples:
            self._compute_prototype(attack_samples, tool_name, SecurityClass.ATTACK.value)

        # Compute decision boundary with data-driven margin
        self._compute_decision_boundary(tool_name)

        # Clean up training embeddings to save memory
        if tool_name in self._training_embeddings:
            del self._training_embeddings[tool_name]

        logger.info(f"Semantic prototypes fitted for {tool_name}: "
                    f"{list(self.prototypes[tool_name].keys())}")

    def predict(self, payload: str, tool_name: Optional[str] = None) -> Optional[DetectionResult]:
        """
        Classify payload using binary prototypical classification.

        Strategy:
        1. Compute distance to benign and attack prototypes
        2. If closer to benign with sufficient margin -> BENIGN
        3. If closer to attack or insufficient margin -> ATTACK
        4. If outside both distributions (anomaly) -> ATTACK (fail-safe)
        """
        if not tool_name or tool_name not in self.prototypes:
            return None

        emb = self._get_embedding(payload)
        prototypes = self.prototypes[tool_name]
        thresholds = self.thresholds.get(tool_name, {})

        # Compute distances
        distances = {}
        for class_name, prototype in prototypes.items():
            similarity = F.cosine_similarity(emb, prototype).item()
            distances[class_name] = float(1.0 - similarity)

        # Get tool-specific thresholds
        anomaly_threshold = thresholds.get("anomaly", 0.5)
        boundary = thresholds.get("boundary", 0.3)
        margin_threshold = thresholds.get("margin", self.DEFAULT_MARGIN_RATIO)

        metadata = {
            "distances": distances,
            "thresholds": {
                "anomaly": anomaly_threshold,
                "boundary": boundary,
                "margin": margin_threshold
            },
            "detector": "semantic"
        }

        benign_dist = distances.get(SecurityClass.BENIGN.value)
        attack_dist = distances.get(SecurityClass.ATTACK.value)

        # Case 1: No benign prototype (shouldn't happen but handle gracefully)
        if benign_dist is None:
            return DetectionResult.attack(
                confidence=0.5,
                reason="No benign prototype for tool",
                metadata=metadata
            )

        # Case 2: Only benign prototype - use threshold-based detection
        if attack_dist is None:
            if benign_dist > anomaly_threshold:
                confidence = min(1.0, 0.6 + (benign_dist - anomaly_threshold) / anomaly_threshold)
                return DetectionResult.attack(
                    confidence=confidence,
                    reason=f"Outside benign distribution (d={benign_dist:.4f} > t={anomaly_threshold:.4f})",
                    metadata=metadata
                )
            elif benign_dist > boundary:
                confidence = 0.5 + 0.4 * (benign_dist - boundary) / (anomaly_threshold - boundary + 1e-9)
                return DetectionResult.attack(
                    confidence=confidence,
                    reason=f"Beyond benign boundary (d={benign_dist:.4f} > b={boundary:.4f})",
                    metadata=metadata
                )
            else:
                confidence = max(0.6, 1.0 - benign_dist / boundary)
                return DetectionResult.benign(
                    confidence=confidence,
                    reason=f"Within benign distribution (d={benign_dist:.4f})",
                    metadata=metadata
                )

        # Case 3: Both prototypes available - relative distance classification
        # Check for anomaly first (outside both distributions)
        if benign_dist > anomaly_threshold and attack_dist > anomaly_threshold:
            confidence = min(1.0, 0.7 + 0.3 * min(benign_dist, attack_dist) / anomaly_threshold)
            return DetectionResult.attack(
                confidence=confidence,
                reason=f"Anomaly: outside both distributions (benign={benign_dist:.4f}, attack={attack_dist:.4f})",
                metadata=metadata
            )

        # Compute relative margin
        margin = (attack_dist - benign_dist) / (attack_dist + benign_dist + 1e-9)
        metadata["margin"] = float(margin)

        # Positive margin = closer to benign, negative = closer to attack
        # Use DATA-DRIVEN margin threshold
        if margin > margin_threshold:
            # Clearly closer to benign
            confidence = min(1.0, 0.6 + margin)
            return DetectionResult.benign(
                confidence=confidence,
                reason=f"Closer to benign prototype (margin={margin:.2%} > {margin_threshold:.2%})",
                metadata=metadata
            )
        elif margin < -margin_threshold:
            # Clearly closer to attack
            confidence = min(1.0, 0.6 + abs(margin))
            return DetectionResult.attack(
                confidence=confidence,
                reason=f"Closer to attack prototype (margin={margin:.2%})",
                metadata=metadata
            )
        else:
            # Ambiguous - fail-safe to attack
            confidence = 0.5 + 0.2 * abs(margin) / margin_threshold
            return DetectionResult.attack(
                confidence=confidence,
                reason=f"Ambiguous classification, fail-safe to attack (margin={margin:.2%})",
                metadata=metadata
            )

    def save_state(self) -> Dict[str, Any]:
        """Return state for persistence."""
        return {
            "prototypes": self.prototypes,
            "thresholds": self.thresholds,
            "class_stats": self.class_stats,
            "version": "3.0",  # Bumped for data-driven margins
            "type": "binary"
        }

    def load_state(self, state: Dict[str, Any]):
        """Load state from persistence."""
        self.prototypes = state.get("prototypes", {})
        self.thresholds = state.get("thresholds", {})
        self.class_stats = state.get("class_stats", {})

        # Backward compatibility: add margin threshold if not present
        for tool_name in self.thresholds:
            if "margin" not in self.thresholds[tool_name]:
                self.thresholds[tool_name]["margin"] = self.DEFAULT_MARGIN_RATIO
