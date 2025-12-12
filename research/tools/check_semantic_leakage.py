#!/usr/bin/env python3
"""
Semantic Data Leakage Checker for MCP Security Gateway.

This script analyzes potential data leakage between training and test sets
by computing semantic similarity using embeddings. Template-based synthetic
data generation can create semantically similar samples even if exact
string matching shows no overlap.

Usage:
    python check_semantic_leakage.py

Output:
    - Semantic similarity analysis
    - Potential leakage warnings
    - Recommendations for dataset improvement
"""

import json
import os
import sys
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Random seed for reproducibility
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# Try to import embedding model
try:
    import torch
    from transformers import AutoTokenizer, AutoModel
    import torch.nn.functional as F
    HAS_TRANSFORMERS = True
    torch.manual_seed(RANDOM_SEED)
except ImportError:
    HAS_TRANSFORMERS = False
    print("Warning: transformers not available. Using string-based similarity only.")


class SemanticLeakageChecker:
    """Check for semantic data leakage between train and test sets."""

    def __init__(self, model_name: str = "distilbert-base-uncased"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None

        if HAS_TRANSFORMERS:
            print(f"Loading embedding model: {model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModel.from_pretrained(model_name)
            self.model.eval()
            print("Model loaded successfully.")

    def _get_embedding(self, text: str) -> np.ndarray:
        """Generate embedding for a text sample."""
        if not HAS_TRANSFORMERS:
            # Fallback: use character n-gram representation
            return self._char_ngram_vector(text)

        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding=True
        )

        with torch.no_grad():
            outputs = self.model(**inputs)

        # Mean pooling
        token_embeddings = outputs.last_hidden_state
        attention_mask = inputs['attention_mask'].unsqueeze(-1)
        sum_embeddings = torch.sum(token_embeddings * attention_mask.float(), dim=1)
        sum_mask = torch.clamp(attention_mask.sum(dim=1), min=1e-9)
        mean_embedding = sum_embeddings / sum_mask

        return F.normalize(mean_embedding, p=2, dim=1).squeeze(0).numpy()

    def _char_ngram_vector(self, text: str, n: int = 3, dim: int = 256) -> np.ndarray:
        """Simple character n-gram based vector (fallback when no transformers)."""
        vector = np.zeros(dim)
        text_lower = text.lower()
        for i in range(len(text_lower) - n + 1):
            ngram = text_lower[i:i+n]
            idx = hash(ngram) % dim
            vector[idx] += 1
        norm = np.linalg.norm(vector)
        return vector / norm if norm > 0 else vector

    def compute_similarity_matrix(
        self,
        samples_a: List[str],
        samples_b: List[str],
        batch_size: int = 32
    ) -> np.ndarray:
        """Compute pairwise cosine similarity matrix between two sample sets."""
        print(f"Computing embeddings for {len(samples_a)} x {len(samples_b)} pairs...")

        # Compute embeddings
        embeddings_a = np.array([self._get_embedding(s) for s in samples_a])
        embeddings_b = np.array([self._get_embedding(s) for s in samples_b])

        # Cosine similarity matrix
        similarity = np.dot(embeddings_a, embeddings_b.T)
        return similarity

    def find_high_similarity_pairs(
        self,
        samples_a: List[str],
        samples_b: List[str],
        threshold: float = 0.95
    ) -> List[Tuple[str, str, float]]:
        """Find pairs with similarity above threshold."""
        similarity_matrix = self.compute_similarity_matrix(samples_a, samples_b)

        high_similarity_pairs = []
        for i in range(len(samples_a)):
            for j in range(len(samples_b)):
                if similarity_matrix[i, j] >= threshold:
                    high_similarity_pairs.append(
                        (samples_a[i], samples_b[j], float(similarity_matrix[i, j]))
                    )

        return high_similarity_pairs

    def analyze_dataset_leakage(
        self,
        train_data: Dict[str, Dict[str, List[str]]],
        test_data: Dict[str, Dict[str, List[str]]],
        similarity_threshold: float = 0.95,
        sample_limit: int = 100
    ) -> Dict:
        """
        Analyze semantic leakage between train and test datasets.

        Args:
            train_data: Training dataset {tool: {class: [samples]}}
            test_data: Test dataset {tool: {class: [samples]}}
            similarity_threshold: Threshold for flagging high similarity
            sample_limit: Max samples per tool/class to analyze (for speed)

        Returns:
            Analysis report dict
        """
        report = {
            "exact_overlaps": 0,
            "high_similarity_pairs": [],
            "per_tool_analysis": {},
            "recommendations": []
        }

        # Get all unique tools
        all_tools = set(train_data.keys()) | set(test_data.keys())
        shared_tools = set(train_data.keys()) & set(test_data.keys())

        print(f"\nAnalyzing {len(all_tools)} total tools ({len(shared_tools)} shared)")
        print("=" * 70)

        for tool in sorted(shared_tools):
            print(f"\nTool: {tool}")
            tool_report = {
                "exact_overlaps": 0,
                "high_similarity_count": 0,
                "mean_similarity": {},
                "max_similarity": {}
            }

            for class_name in ['benign', 'attack']:
                train_samples = train_data.get(tool, {}).get(class_name, [])[:sample_limit]
                test_samples = test_data.get(tool, {}).get(class_name, [])[:sample_limit]

                if not train_samples or not test_samples:
                    continue

                # Convert to strings
                train_strings = [json.dumps(s) if isinstance(s, dict) else str(s)
                                for s in train_samples]
                test_strings = [json.dumps(s) if isinstance(s, dict) else str(s)
                               for s in test_samples]

                # Check exact overlap
                exact_overlap = set(train_strings) & set(test_strings)
                tool_report["exact_overlaps"] += len(exact_overlap)
                report["exact_overlaps"] += len(exact_overlap)

                if exact_overlap:
                    print(f"  [WARNING] {class_name}: {len(exact_overlap)} exact overlaps!")

                # Compute semantic similarity
                if len(train_strings) > 0 and len(test_strings) > 0:
                    similarity = self.compute_similarity_matrix(train_strings, test_strings)
                    mean_sim = float(np.mean(similarity))
                    max_sim = float(np.max(similarity))

                    tool_report["mean_similarity"][class_name] = mean_sim
                    tool_report["max_similarity"][class_name] = max_sim

                    print(f"  {class_name}: mean_sim={mean_sim:.3f}, max_sim={max_sim:.3f}")

                    # Count high similarity pairs
                    high_sim_count = np.sum(similarity >= similarity_threshold)
                    if high_sim_count > 0:
                        tool_report["high_similarity_count"] += high_sim_count
                        print(f"    [WARNING] {high_sim_count} pairs with similarity >= {similarity_threshold}")

                        # Get top examples
                        indices = np.argwhere(similarity >= similarity_threshold)
                        for idx in indices[:3]:  # Show top 3
                            i, j = idx
                            report["high_similarity_pairs"].append({
                                "tool": tool,
                                "class": class_name,
                                "train_sample": train_strings[i][:100],
                                "test_sample": test_strings[j][:100],
                                "similarity": float(similarity[i, j])
                            })

            report["per_tool_analysis"][tool] = tool_report

        # Generate recommendations
        if report["exact_overlaps"] > 0:
            report["recommendations"].append(
                f"CRITICAL: {report['exact_overlaps']} exact overlapping samples detected. "
                "Remove these from test set to prevent data leakage."
            )

        high_sim_total = sum(t.get("high_similarity_count", 0)
                            for t in report["per_tool_analysis"].values())
        if high_sim_total > 0:
            report["recommendations"].append(
                f"WARNING: {high_sim_total} semantically similar pairs (>={similarity_threshold}) detected. "
                "Consider using disjoint template pools for synthetic data generation."
            )

        # Check for tools only in one set
        train_only = set(train_data.keys()) - set(test_data.keys())
        test_only = set(test_data.keys()) - set(train_data.keys())

        if test_only:
            report["recommendations"].append(
                f"INFO: {len(test_only)} tools in test set but not in training: {list(test_only)[:5]}... "
                "This tests cross-tool generalization, NOT zero-day attack detection."
            )

        return report


def load_dataset(path: str) -> Dict:
    """Load dataset from JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    data.pop('_metadata', None)
    return data


def main():
    print("=" * 70)
    print("SEMANTIC DATA LEAKAGE ANALYSIS")
    print("=" * 70)

    # Paths
    data_dir = PROJECT_ROOT / "research" / "data"
    train_path = data_dir / "training_dataset.json"
    test_path = data_dir / "test_dataset.json"

    # Load datasets
    print(f"\nLoading training data: {train_path}")
    train_data = load_dataset(str(train_path))
    print(f"  {len(train_data)} tools loaded")

    print(f"\nLoading test data: {test_path}")
    test_data = load_dataset(str(test_path))
    print(f"  {len(test_data)} tools loaded")

    # Initialize checker
    checker = SemanticLeakageChecker()

    # Run analysis
    report = checker.analyze_dataset_leakage(
        train_data, test_data,
        similarity_threshold=0.95,
        sample_limit=50  # Limit for faster analysis
    )

    # Print summary
    print("\n" + "=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)

    print(f"\nExact Overlaps: {report['exact_overlaps']}")
    print(f"High Similarity Pairs (>=0.95): {len(report['high_similarity_pairs'])}")

    if report["high_similarity_pairs"]:
        print("\nExample High-Similarity Pairs:")
        for pair in report["high_similarity_pairs"][:5]:
            print(f"\n  Tool: {pair['tool']}, Class: {pair['class']}")
            print(f"  Similarity: {pair['similarity']:.4f}")
            print(f"  Train: {pair['train_sample'][:60]}...")
            print(f"  Test:  {pair['test_sample'][:60]}...")

    print("\n" + "-" * 70)
    print("RECOMMENDATIONS:")
    print("-" * 70)
    for i, rec in enumerate(report["recommendations"], 1):
        print(f"\n{i}. {rec}")

    # Save report
    report_path = data_dir / "semantic_leakage_report.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f"\n\nFull report saved to: {report_path}")

    # Return exit code based on leakage severity
    if report["exact_overlaps"] > 0:
        print("\n[FAIL] Exact data leakage detected!")
        return 1
    elif len(report["high_similarity_pairs"]) > 10:
        print("\n[WARNING] Significant semantic similarity detected.")
        return 0
    else:
        print("\n[PASS] No significant data leakage detected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
