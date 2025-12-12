"""
Train MCP Security Gateway detector models using binary classification.

Training data format (JSON):
{
    "tool_name": {
        "benign": ["safe payload 1", "safe payload 2", ...],
        "attack": ["attack payload 1", "attack payload 2", ...]
    }
}
"""

import json
import os
import sys
import logging
import argparse
import torch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from mcp_bridge.src.core.detectors.statistical import StatisticalFeatureDetector
from mcp_bridge.src.core.detectors.semantic import SemanticDetector
from mcp_bridge.src.core.detectors.maml import MAMLDetector, MAMLConfig

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

RESEARCH_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_PATH = os.path.join(RESEARCH_DIR, "data", "owasp_training_dataset.json")
MODELS_DIR = os.path.join(RESEARCH_DIR, "trained_models")


def validate_training_data(data: dict) -> None:
    """Validate training data format."""
    for tool_name, samples in data.items():
        if not isinstance(samples, dict):
            raise ValueError(f"Tool '{tool_name}': expected dict, got {type(samples).__name__}")
        if "benign" not in samples:
            raise ValueError(f"Tool '{tool_name}': missing 'benign' key")
        if "attack" not in samples:
            raise ValueError(f"Tool '{tool_name}': missing 'attack' key")


def train(train_maml: bool = False, maml_epochs: int = 100) -> None:
    """
    Train detector models using binary classification (benign vs attack).

    Args:
        train_maml: Whether to train the MAML meta-learning detector
        maml_epochs: Number of meta-training epochs for MAML
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    logger.info(f"Loading training data from {DATA_PATH}")
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    validate_training_data(data)

    # Initialize detectors
    stat_detector = StatisticalFeatureDetector()
    sem_detector = SemanticDetector(model_name="distilbert-base-uncased")
    maml_data = {} if train_maml else None

    # Train on each tool
    for tool_name, samples in data.items():
        benign = samples["benign"]
        attack = samples["attack"]

        logger.info(f"Training: {tool_name} (benign={len(benign)}, attack={len(attack)})")

        stat_detector.fit(tool_name, benign, attack)
        sem_detector.fit(tool_name, benign, attack)

        if train_maml:
            maml_data[tool_name] = {"benign": benign, "attack": attack}

    # Save models
    stat_path = os.path.join(MODELS_DIR, "statistical_model.pt")
    torch.save(stat_detector.save_state(), stat_path)
    logger.info(f"Saved: {stat_path}")

    sem_path = os.path.join(MODELS_DIR, "semantic_model.pt")
    torch.save(sem_detector.save_state(), sem_path)
    logger.info(f"Saved: {sem_path}")

    # Train MAML if enabled
    if train_maml:
        logger.info("Training MAML detector...")

        maml_config = MAMLConfig(
            meta_lr=0.001,
            inner_lr=0.01,
            adaptation_steps=5,
            first_order=True,
            ways=2,
            shots=5,
            queries=5,
            hidden_dim=256,
            num_meta_epochs=maml_epochs,
            confidence_threshold=0.6
        )

        maml_detector = MAMLDetector(
            model_name="distilbert-base-uncased",
            config=maml_config
        )
        maml_detector.meta_train(maml_data, verbose=True)

        maml_path = os.path.join(MODELS_DIR, "maml_model.pt")
        torch.save(maml_detector.save_state(), maml_path)
        logger.info(f"Saved: {maml_path}")

        history = maml_detector.training_history
        if history.get("meta_loss"):
            logger.info(f"MAML final loss: {history['meta_loss'][-1]:.4f}, "
                       f"accuracy: {history['meta_accuracy'][-1]:.3f}")

    logger.info("Training complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train MCP Security Gateway detector models"
    )
    parser.add_argument(
        "--maml",
        action="store_true",
        help="Enable MAML meta-learning detector training"
    )
    parser.add_argument(
        "--maml-epochs",
        type=int,
        default=100,
        help="Number of meta-training epochs for MAML (default: 100)"
    )

    args = parser.parse_args()
    train(train_maml=args.maml, maml_epochs=args.maml_epochs)
