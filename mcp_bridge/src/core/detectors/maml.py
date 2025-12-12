"""
MAML (Model-Agnostic Meta-Learning) Detector for MCP Security Gateway.

This detector implements meta-learning for few-shot binary security classification,
allowing rapid adaptation to new tools with minimal training examples.

Based on:
- Finn et al. "Model-Agnostic Meta-Learning for Fast Adaptation of Deep Networks" (ICML 2017)

Key Features:
- Few-shot learning: Adapt to new tools with K examples per class (configurable)
- Fast adaptation: 1-5 gradient steps for task-specific fine-tuning
- Meta-learned initialization: Learns a good starting point for all tools
- Binary classification: BENIGN vs ATTACK for fast, accurate decisions
- Proper few-shot evaluation: evaluate_few_shot() method for K-shot testing
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel
import numpy as np
import logging
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
from .base import BaseDetector, DetectionResult, SecurityClass

logger = logging.getLogger(__name__)

# Random seed for reproducibility
RANDOM_SEED = 42
torch.manual_seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)


@dataclass
class MAMLConfig:
    """Configuration for MAML detector with tunable hyperparameters."""

    # Meta-learning parameters
    meta_lr: float = 0.001  # Outer loop learning rate (meta-update)
    inner_lr: float = 0.01  # Inner loop learning rate (task adaptation)
    adaptation_steps: int = 5  # Number of gradient steps for task adaptation
    first_order: bool = True  # Use first-order MAML (faster, similar performance)

    # Few-shot task parameters
    ways: int = 2  # Number of classes (benign, attack)
    shots: int = 5  # Examples per class for adaptation (support set)
    queries: int = 5  # Examples per class for evaluation (query set)

    # Training parameters
    meta_batch_size: int = 4  # Number of tasks per meta-update
    num_meta_epochs: int = 100  # Meta-training epochs

    # Early stopping parameters
    early_stopping_patience: int = 10
    early_stopping_min_delta: float = 0.001
    early_stopping_min_epochs: int = 20

    # Model architecture
    hidden_dim: int = 256  # Hidden layer dimension
    embedding_dim: int = 768  # DistilBERT embedding dimension

    # Classification parameters
    confidence_threshold: float = 0.6  # Minimum confidence for benign
    temperature: float = 1.0  # Softmax temperature for calibration


class MAMLClassifier(nn.Module):
    """
    Neural network classifier for MAML-based binary security detection.

    Architecture:
    - Input: DistilBERT embeddings (768-dim)
    - Hidden: Linear -> ReLU -> Dropout -> Linear
    - Output: 2-class logits (benign, attack)
    """

    def __init__(self, config: MAMLConfig):
        super().__init__()
        self.config = config

        self.classifier = nn.Sequential(
            nn.Linear(config.embedding_dim, config.hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(config.hidden_dim, config.hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(config.hidden_dim // 2, config.ways)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass returning class logits."""
        return self.classifier(x)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Return softmax probabilities."""
        logits = self.forward(x)
        return F.softmax(logits / self.config.temperature, dim=-1)


@dataclass
class FewShotEvalResult:
    """Results from few-shot evaluation."""
    k_shots: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    n_trials: int
    accuracy_std: float
    per_trial_accuracies: List[float]


class MAMLDetector(BaseDetector):
    """
    MAML-based meta-learning detector for binary security classification.

    Key Advantages:
    1. Few-shot adaptation: Learn new tools with minimal examples (K per class)
    2. Transfer learning: Meta-learned initialization transfers across tools
    3. Fast inference: Single forward pass after adaptation
    4. Calibrated confidence: Temperature-scaled softmax probabilities

    Binary Classification Strategy:
    1. Encode payload using DistilBERT
    2. Forward pass through adapted classifier
    3. Return class with higher probability
    4. Low confidence predictions treated as attacks (fail-safe)

    IMPORTANT: Use evaluate_few_shot() to properly test K-shot performance.
    The _adapt_to_tool() method uses ALL training data, which is NOT few-shot.
    """

    CLASS_NAMES = [
        SecurityClass.BENIGN.value,
        SecurityClass.ATTACK.value
    ]

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        config: Optional[MAMLConfig] = None,
        device: Optional[str] = None
    ):
        """
        Initialize MAML detector.

        Args:
            model_name: HuggingFace model for embeddings
            config: MAML hyperparameter configuration
            device: torch device (auto-detected if None)
        """
        # Set random seed
        torch.manual_seed(RANDOM_SEED)
        np.random.seed(RANDOM_SEED)

        self.config = config or MAMLConfig()
        self.model_name = model_name
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # Initialize embedding model
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.encoder = AutoModel.from_pretrained(model_name)
        self.encoder.eval()
        self.encoder.to(self.device)

        # Initialize meta-learned classifier
        self.meta_model = MAMLClassifier(self.config).to(self.device)

        # Tool-specific adapted models (after few-shot adaptation)
        self.adapted_models: Dict[str, nn.Module] = {}

        # Store adaptation mode: "full" (all data) or "few_shot" (K examples)
        self.adaptation_mode: Dict[str, str] = {}

        # Training statistics for monitoring
        self.training_history: Dict[str, List[float]] = {
            "meta_loss": [],
            "meta_accuracy": []
        }

        # Tool-specific training data cache for adaptation
        self.tool_data: Dict[str, Dict[str, List[str]]] = {}

        # Few-shot evaluation results cache
        self.few_shot_eval_cache: Dict[str, Dict[int, FewShotEvalResult]] = {}

        logger.info(f"Initialized MAML Detector (device={self.device}, binary classification)")
        logger.info(f"  Config: inner_lr={self.config.inner_lr}, "
                   f"adaptation_steps={self.config.adaptation_steps}, "
                   f"first_order={self.config.first_order}")

    def _get_embedding(self, text: str) -> torch.Tensor:
        """Generate normalized embedding using DistilBERT."""
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding=True
        ).to(self.device)

        with torch.no_grad():
            outputs = self.encoder(**inputs)

        # Mean pooling over tokens
        token_embeddings = outputs.last_hidden_state
        attention_mask = inputs['attention_mask'].unsqueeze(-1)
        sum_embeddings = torch.sum(token_embeddings * attention_mask.float(), dim=1)
        sum_mask = torch.clamp(attention_mask.sum(dim=1), min=1e-9)
        mean_embedding = sum_embeddings / sum_mask

        return F.normalize(mean_embedding, p=2, dim=1)

    def _get_batch_embeddings(self, texts: List[str]) -> torch.Tensor:
        """Generate embeddings for a batch of texts."""
        if not texts:
            return torch.empty(0, self.config.embedding_dim, device=self.device)

        inputs = self.tokenizer(
            texts,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding=True
        ).to(self.device)

        with torch.no_grad():
            outputs = self.encoder(**inputs)

        token_embeddings = outputs.last_hidden_state
        attention_mask = inputs['attention_mask'].unsqueeze(-1)
        sum_embeddings = torch.sum(token_embeddings * attention_mask.float(), dim=1)
        sum_mask = torch.clamp(attention_mask.sum(dim=1), min=1e-9)
        mean_embeddings = sum_embeddings / sum_mask

        return F.normalize(mean_embeddings, p=2, dim=1)

    def _create_task_batch(
        self,
        tool_data: Dict[str, List[str]],
        shots: int,
        queries: int
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Create a few-shot task batch for meta-learning.

        Returns:
            support_x: Support set embeddings (ways * shots, embedding_dim)
            support_y: Support set labels (ways * shots,)
            query_x: Query set embeddings (ways * queries, embedding_dim)
            query_y: Query set labels (ways * queries,)
        """
        support_texts = []
        support_labels = []
        query_texts = []
        query_labels = []

        for class_idx, class_name in enumerate(self.CLASS_NAMES):
            samples = tool_data.get(class_name, [])

            if len(samples) < shots + queries:
                # Not enough samples - use what we have with repetition
                available = len(samples)
                if available == 0:
                    continue

                indices = np.random.choice(available, shots + queries, replace=True)
                selected = [samples[i] for i in indices]
            else:
                indices = np.random.choice(len(samples), shots + queries, replace=False)
                selected = [samples[i] for i in indices]

            support_texts.extend(selected[:shots])
            support_labels.extend([class_idx] * shots)
            query_texts.extend(selected[shots:shots + queries])
            query_labels.extend([class_idx] * queries)

        # Generate embeddings
        support_x = self._get_batch_embeddings(support_texts)
        query_x = self._get_batch_embeddings(query_texts)
        support_y = torch.tensor(support_labels, device=self.device)
        query_y = torch.tensor(query_labels, device=self.device)

        return support_x, support_y, query_x, query_y

    def _inner_loop(
        self,
        model: nn.Module,
        support_x: torch.Tensor,
        support_y: torch.Tensor,
        adaptation_steps: int,
        inner_lr: float
    ) -> nn.Module:
        """
        Perform inner loop adaptation (task-specific fine-tuning).
        """
        # Clone model for adaptation
        adapted_model = MAMLClassifier(self.config).to(self.device)
        adapted_model.load_state_dict(model.state_dict())

        # Create optimizer for inner loop
        optimizer = torch.optim.SGD(adapted_model.parameters(), lr=inner_lr)

        # Perform adaptation steps
        for _ in range(adaptation_steps):
            optimizer.zero_grad()
            logits = adapted_model(support_x)
            loss = F.cross_entropy(logits, support_y)
            loss.backward()
            optimizer.step()

        return adapted_model

    def _inner_loop_functional(
        self,
        params: Dict[str, torch.Tensor],
        support_x: torch.Tensor,
        support_y: torch.Tensor,
        adaptation_steps: int,
        inner_lr: float
    ) -> Dict[str, torch.Tensor]:
        """Perform inner loop adaptation using functional approach."""
        adapted_params = {k: v.clone().requires_grad_(True) for k, v in params.items()}

        for _ in range(adaptation_steps):
            logits = self._functional_forward(adapted_params, support_x)
            loss = F.cross_entropy(logits, support_y)

            grads = torch.autograd.grad(
                loss,
                list(adapted_params.values()),
                create_graph=not self.config.first_order
            )

            adapted_params = {
                k: v - inner_lr * g
                for (k, v), g in zip(adapted_params.items(), grads)
            }

        return adapted_params

    def _functional_forward(
        self,
        params: Dict[str, torch.Tensor],
        x: torch.Tensor
    ) -> torch.Tensor:
        """Functional forward pass through the classifier."""
        # Layer 1: Linear -> ReLU
        x = F.linear(x, params["classifier.0.weight"], params["classifier.0.bias"])
        x = F.relu(x)

        # Layer 2: Linear -> ReLU
        x = F.linear(x, params["classifier.3.weight"], params["classifier.3.bias"])
        x = F.relu(x)

        # Layer 3: Linear (output)
        x = F.linear(x, params["classifier.6.weight"], params["classifier.6.bias"])

        return x

    def _compute_maml_loss(
        self,
        tasks: List[Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]]
    ) -> Tuple[torch.Tensor, float]:
        """Compute MAML meta-loss across multiple tasks."""
        task_losses = []
        total_correct = 0
        total_queries = 0

        meta_params = dict(self.meta_model.named_parameters())

        for support_x, support_y, query_x, query_y in tasks:
            if len(support_x) == 0 or len(query_x) == 0:
                continue

            adapted_params = self._inner_loop_functional(
                meta_params,
                support_x,
                support_y,
                self.config.adaptation_steps,
                self.config.inner_lr
            )

            query_logits = self._functional_forward(adapted_params, query_x)
            task_loss = F.cross_entropy(query_logits, query_y)
            task_losses.append(task_loss)

            with torch.no_grad():
                preds = query_logits.argmax(dim=-1)
                total_correct += (preds == query_y).sum().item()
                total_queries += len(query_y)

        if not task_losses:
            return torch.tensor(0.0, device=self.device, requires_grad=True), 0.0

        meta_loss = torch.stack(task_losses).mean()
        meta_accuracy = total_correct / max(total_queries, 1)

        return meta_loss, meta_accuracy

    def meta_train(
        self,
        all_tool_data: Dict[str, Dict[str, List[str]]],
        num_epochs: Optional[int] = None,
        verbose: bool = True
    ):
        """
        Perform meta-training across all tools with early stopping.
        """
        num_epochs = num_epochs or self.config.num_meta_epochs
        self.tool_data = all_tool_data

        meta_optimizer = torch.optim.Adam(
            self.meta_model.parameters(),
            lr=self.config.meta_lr
        )

        tool_names = list(all_tool_data.keys())
        best_loss = float('inf')
        patience_counter = 0
        best_model_state = None

        if verbose:
            logger.info(f"Starting MAML meta-training for up to {num_epochs} epochs")
            logger.info(f"  Tools: {tool_names}")

        for epoch in range(num_epochs):
            tasks = []
            sampled_tools = np.random.choice(
                tool_names,
                min(self.config.meta_batch_size, len(tool_names)),
                replace=len(tool_names) < self.config.meta_batch_size
            )

            for tool_name in sampled_tools:
                task = self._create_task_batch(
                    all_tool_data[tool_name],
                    self.config.shots,
                    self.config.queries
                )
                tasks.append(task)

            meta_optimizer.zero_grad()
            meta_loss, meta_accuracy = self._compute_maml_loss(tasks)
            meta_loss.backward()
            meta_optimizer.step()

            current_loss = meta_loss.item()
            self.training_history["meta_loss"].append(current_loss)
            self.training_history["meta_accuracy"].append(meta_accuracy)

            # Early stopping logic
            if epoch >= self.config.early_stopping_min_epochs:
                if current_loss < best_loss - self.config.early_stopping_min_delta:
                    best_loss = current_loss
                    patience_counter = 0
                    best_model_state = {
                        k: v.clone().cpu() for k, v in self.meta_model.state_dict().items()
                    }
                else:
                    patience_counter += 1

                if patience_counter >= self.config.early_stopping_patience:
                    if verbose:
                        logger.info(f"Early stopping at epoch {epoch + 1}")
                    if best_model_state is not None:
                        self.meta_model.load_state_dict(
                            {k: v.to(self.device) for k, v in best_model_state.items()}
                        )
                    break
            else:
                if current_loss < best_loss:
                    best_loss = current_loss
                    best_model_state = {
                        k: v.clone().cpu() for k, v in self.meta_model.state_dict().items()
                    }

            if verbose and (epoch + 1) % 10 == 0:
                logger.info(f"  Epoch {epoch + 1}/{num_epochs}: loss={current_loss:.4f}, acc={meta_accuracy:.3f}")

        if verbose:
            logger.info(f"Meta-training complete. Final loss: {current_loss:.4f}")

        # Adapt to each tool using ALL data (not few-shot)
        # NOTE: This is NOT the claimed few-shot capability
        for tool_name in tool_names:
            self._adapt_to_tool_full(tool_name, all_tool_data[tool_name])

    def _adapt_to_tool_full(self, tool_name: str, tool_data: Dict[str, List[str]]):
        """
        Create a tool-specific adapted model using ALL available data.

        WARNING: This is NOT few-shot learning. This method uses all training data.
        Use adapt_few_shot() for true K-shot adaptation.
        """
        all_texts = []
        all_labels = []

        for class_idx, class_name in enumerate(self.CLASS_NAMES):
            samples = tool_data.get(class_name, [])
            all_texts.extend(samples)
            all_labels.extend([class_idx] * len(samples))

        if not all_texts:
            logger.warning(f"No training data for tool {tool_name}, skipping adaptation")
            return

        support_x = self._get_batch_embeddings(all_texts)
        support_y = torch.tensor(all_labels, device=self.device)

        adapted = self._inner_loop(
            self.meta_model,
            support_x,
            support_y,
            self.config.adaptation_steps * 2,
            self.config.inner_lr
        )

        adapted.eval()
        self.adapted_models[tool_name] = adapted
        self.adaptation_mode[tool_name] = "full"

        logger.info(f"  Adapted MAML model for {tool_name} using FULL DATA "
                   f"({len(all_texts)} samples, {len(set(all_labels))} classes)")

    def adapt_few_shot(
        self,
        tool_name: str,
        tool_data: Dict[str, List[str]],
        k_shots: int
    ) -> nn.Module:
        """
        Create a tool-specific adapted model using EXACTLY K examples per class.

        This is TRUE few-shot adaptation that matches the MAML claims.

        Args:
            tool_name: Name of the tool
            tool_data: Dict with "benign" and "attack" sample lists
            k_shots: Number of examples to use per class

        Returns:
            Adapted model (also stored in self.adapted_models)
        """
        support_texts = []
        support_labels = []

        for class_idx, class_name in enumerate(self.CLASS_NAMES):
            samples = tool_data.get(class_name, [])

            if len(samples) < k_shots:
                logger.warning(f"Only {len(samples)} {class_name} samples for {tool_name}, "
                              f"need {k_shots}. Using with replacement.")
                indices = np.random.choice(len(samples), k_shots, replace=True)
            else:
                indices = np.random.choice(len(samples), k_shots, replace=False)

            selected = [samples[i] for i in indices]
            support_texts.extend(selected)
            support_labels.extend([class_idx] * k_shots)

        support_x = self._get_batch_embeddings(support_texts)
        support_y = torch.tensor(support_labels, device=self.device)

        adapted = self._inner_loop(
            self.meta_model,
            support_x,
            support_y,
            self.config.adaptation_steps,
            self.config.inner_lr
        )

        adapted.eval()
        self.adapted_models[tool_name] = adapted
        self.adaptation_mode[tool_name] = f"few_shot_{k_shots}"

        logger.info(f"  Adapted MAML model for {tool_name} using {k_shots}-SHOT "
                   f"({k_shots * 2} total samples)")

        return adapted

    def evaluate_few_shot(
        self,
        tool_name: str,
        tool_data: Dict[str, List[str]],
        k_shots: int,
        n_trials: int = 20,
        n_query: int = 15
    ) -> FewShotEvalResult:
        """
        Properly evaluate K-shot learning performance.

        This method:
        1. Randomly samples K examples per class for adaptation
        2. Uses remaining examples as test set
        3. Repeats n_trials times to get mean/std

        Args:
            tool_name: Name of the tool to evaluate
            tool_data: Dict with "benign" and "attack" sample lists
            k_shots: Number of shots per class
            n_trials: Number of random trials
            n_query: Number of query samples per class per trial

        Returns:
            FewShotEvalResult with accuracy, precision, recall, F1, and statistics
        """
        logger.info(f"Evaluating {k_shots}-shot performance for {tool_name} ({n_trials} trials)")

        trial_accuracies = []
        all_tp, all_fp, all_tn, all_fn = 0, 0, 0, 0

        for trial in range(n_trials):
            # Set seed for reproducibility within trial
            np.random.seed(RANDOM_SEED + trial)

            # Sample K-shot support set and query set
            support_texts = []
            support_labels = []
            query_texts = []
            query_labels = []

            for class_idx, class_name in enumerate(self.CLASS_NAMES):
                samples = tool_data.get(class_name, [])

                if len(samples) < k_shots + n_query:
                    # Not enough samples - skip this class for this trial
                    logger.warning(f"Trial {trial}: {class_name} has only {len(samples)} samples, "
                                  f"need {k_shots + n_query}")
                    continue

                # Random split
                indices = np.random.permutation(len(samples))
                support_indices = indices[:k_shots]
                query_indices = indices[k_shots:k_shots + n_query]

                support_texts.extend([samples[i] for i in support_indices])
                support_labels.extend([class_idx] * k_shots)
                query_texts.extend([samples[i] for i in query_indices])
                query_labels.extend([class_idx] * n_query)

            if len(support_texts) < k_shots * 2 or len(query_texts) < n_query * 2:
                logger.warning(f"Trial {trial}: Insufficient data, skipping")
                continue

            # Adapt using only K-shot support set
            support_x = self._get_batch_embeddings(support_texts)
            support_y = torch.tensor(support_labels, device=self.device)

            adapted = self._inner_loop(
                self.meta_model,
                support_x,
                support_y,
                self.config.adaptation_steps,
                self.config.inner_lr
            )
            adapted.eval()

            # Evaluate on query set
            query_x = self._get_batch_embeddings(query_texts)
            query_y = torch.tensor(query_labels, device=self.device)

            with torch.no_grad():
                logits = adapted(query_x)
                preds = logits.argmax(dim=-1)

            # Compute metrics (class 1 = attack is positive)
            tp = ((preds == 1) & (query_y == 1)).sum().item()
            fp = ((preds == 1) & (query_y == 0)).sum().item()
            tn = ((preds == 0) & (query_y == 0)).sum().item()
            fn = ((preds == 0) & (query_y == 1)).sum().item()

            all_tp += tp
            all_fp += fp
            all_tn += tn
            all_fn += fn

            trial_acc = (tp + tn) / (tp + fp + tn + fn)
            trial_accuracies.append(trial_acc)

        # Compute aggregate metrics
        total = all_tp + all_fp + all_tn + all_fn
        accuracy = (all_tp + all_tn) / total if total > 0 else 0.0
        precision = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0.0
        recall = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        result = FewShotEvalResult(
            k_shots=k_shots,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            n_trials=len(trial_accuracies),
            accuracy_std=float(np.std(trial_accuracies)) if trial_accuracies else 0.0,
            per_trial_accuracies=trial_accuracies
        )

        # Cache result
        if tool_name not in self.few_shot_eval_cache:
            self.few_shot_eval_cache[tool_name] = {}
        self.few_shot_eval_cache[tool_name][k_shots] = result

        logger.info(f"  {k_shots}-shot results: acc={accuracy:.3f}±{result.accuracy_std:.3f}, "
                   f"P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}")

        return result

    def evaluate_few_shot_sweep(
        self,
        tool_name: str,
        tool_data: Dict[str, List[str]],
        k_values: List[int] = [1, 2, 5, 10, 15, 20],
        n_trials: int = 20
    ) -> Dict[int, FewShotEvalResult]:
        """
        Evaluate few-shot performance across multiple K values.

        Args:
            tool_name: Name of the tool
            tool_data: Training data
            k_values: List of K values to test
            n_trials: Trials per K value

        Returns:
            Dict mapping K -> FewShotEvalResult
        """
        results = {}
        for k in k_values:
            # Check if we have enough data
            min_samples = min(
                len(tool_data.get(SecurityClass.BENIGN.value, [])),
                len(tool_data.get(SecurityClass.ATTACK.value, []))
            )
            if min_samples < k + 15:  # k for support + 15 for query
                logger.warning(f"Skipping K={k} for {tool_name}: only {min_samples} samples per class")
                continue

            results[k] = self.evaluate_few_shot(tool_name, tool_data, k, n_trials)

        return results

    def fit(
        self,
        tool_name: str,
        benign_samples: List[str],
        attack_samples: Optional[List[str]] = None,
        k_shots: Optional[int] = None
    ):
        """
        Fit detector for a single tool (API compatible with other detectors).

        Args:
            tool_name: Name of the tool to fit
            benign_samples: List of benign payload examples
            attack_samples: List of attack payload examples
            k_shots: If provided, use only K examples per class (true few-shot).
                     If None (default), use all provided samples.

        NOTE: When k_shots is None, this uses ALL provided samples, not K-shot.
        Set k_shots to an integer (e.g., 5) for true few-shot adaptation.
        """
        tool_data = {
            SecurityClass.BENIGN.value: benign_samples or [],
            SecurityClass.ATTACK.value: attack_samples or []
        }

        self.tool_data[tool_name] = tool_data

        if k_shots is not None:
            # True few-shot adaptation
            self.adapt_few_shot(tool_name, tool_data, k_shots)
        else:
            # Full data adaptation (not few-shot)
            self._adapt_to_tool_full(tool_name, tool_data)

    def predict(
        self,
        payload: str,
        tool_name: Optional[str] = None
    ) -> Optional[DetectionResult]:
        """
        Classify payload using adapted MAML model.

        Strategy:
        1. Get adapted model for tool (or use meta-model if not adapted)
        2. Compute class probabilities
        3. Classify as ATTACK if attack_prob > benign_prob or low confidence
        4. Classify as BENIGN only with high confidence
        """
        if tool_name is None:
            return None

        # Get model for this tool
        model = self.adapted_models.get(tool_name, self.meta_model)
        model.eval()

        # Get embedding
        embedding = self._get_embedding(payload)

        # Get class probabilities
        with torch.no_grad():
            probs = model.predict_proba(embedding).squeeze(0)

        benign_prob = probs[0].item()
        attack_prob = probs[1].item()

        metadata = {
            "benign_prob": benign_prob,
            "attack_prob": attack_prob,
            "detector": "maml",
            "adapted": tool_name in self.adapted_models,
            "adaptation_mode": self.adaptation_mode.get(tool_name, "none")
        }

        # Low confidence - fail-safe to attack
        if max(benign_prob, attack_prob) < self.config.confidence_threshold:
            return DetectionResult.attack(
                confidence=1.0 - max(benign_prob, attack_prob),
                reason=f"Low confidence, fail-safe to attack (max_prob={max(benign_prob, attack_prob):.3f})",
                metadata=metadata
            )

        # Classify based on probabilities
        if attack_prob >= benign_prob:
            return DetectionResult.attack(
                confidence=attack_prob,
                reason=f"MAML classifier: attack (p={attack_prob:.3f})",
                metadata=metadata
            )
        else:
            return DetectionResult.benign(
                confidence=benign_prob,
                reason=f"MAML classifier: benign (p={benign_prob:.3f})",
                metadata=metadata
            )

    def save_state(self) -> Dict[str, Any]:
        """Save MAML detector state for persistence."""
        return {
            "meta_model_state": self.meta_model.state_dict(),
            "adapted_models_state": {
                name: model.state_dict()
                for name, model in self.adapted_models.items()
            },
            "adaptation_mode": self.adaptation_mode,
            "config": {
                "meta_lr": self.config.meta_lr,
                "inner_lr": self.config.inner_lr,
                "adaptation_steps": self.config.adaptation_steps,
                "first_order": self.config.first_order,
                "ways": self.config.ways,
                "shots": self.config.shots,
                "queries": self.config.queries,
                "hidden_dim": self.config.hidden_dim,
                "embedding_dim": self.config.embedding_dim,
                "confidence_threshold": self.config.confidence_threshold,
                "temperature": self.config.temperature
            },
            "training_history": self.training_history,
            "few_shot_eval_cache": {
                tool: {k: vars(v) for k, v in results.items()}
                for tool, results in self.few_shot_eval_cache.items()
            },
            "tool_data_keys": list(self.tool_data.keys()),
            "version": "3.0",  # Bumped for few-shot evaluation
            "type": "binary"
        }

    def load_state(self, state: Dict[str, Any]):
        """Load MAML detector state from persistence."""
        config_dict = state.get("config", {})
        self.config = MAMLConfig(**config_dict)

        self.meta_model = MAMLClassifier(self.config).to(self.device)

        if "meta_model_state" in state:
            self.meta_model.load_state_dict(state["meta_model_state"])

        self.adapted_models = {}
        for name, model_state in state.get("adapted_models_state", {}).items():
            model = MAMLClassifier(self.config).to(self.device)
            model.load_state_dict(model_state)
            model.eval()
            self.adapted_models[name] = model

        self.adaptation_mode = state.get("adaptation_mode", {})

        self.training_history = state.get("training_history", {
            "meta_loss": [],
            "meta_accuracy": []
        })

        # Load few-shot eval cache
        self.few_shot_eval_cache = {}
        for tool, results in state.get("few_shot_eval_cache", {}).items():
            self.few_shot_eval_cache[tool] = {
                k: FewShotEvalResult(**v) for k, v in results.items()
            }

        logger.info(f"Loaded MAML state with {len(self.adapted_models)} adapted tools")
