#!/usr/bin/env python3
"""
Create OWASP-compliant datasets for ML security model training and evaluation.

OWASP Recommendations:
- Training: 50/50 ratio (benign/attack) - balanced for learning decision boundaries
- Testing: 90/10 ratio (benign/attack) - realistic distribution, tests false positive rate
- Validation: 50/50 ratio (benign/attack) - balanced for hyperparameter tuning

Key Requirements:
- No overlap between datasets
- Each MCP tool should have a balanced dataset within itself
- Use existing data from previous datasets
"""

import json
import random
from pathlib import Path
from collections import defaultdict
from typing import Dict, Set, List, Tuple

# Configuration
RANDOM_SEED = 42
DATA_DIR = Path(__file__).parent.parent / "data"

# Dataset split ratios
TRAIN_RATIO = 0.6  # 60% for training
VAL_RATIO = 0.2    # 20% for validation
TEST_RATIO = 0.2   # 20% for testing

# Target ratios within each dataset
TRAIN_BENIGN_RATIO = 0.50  # 50/50 for training
VAL_BENIGN_RATIO = 0.50    # 50/50 for validation
TEST_BENIGN_RATIO = 0.90   # 90/10 for testing (realistic)


def load_dataset(filepath: Path) -> Dict:
    """Load a dataset from JSON file."""
    if not filepath.exists():
        print(f"Warning: {filepath} does not exist")
        return {}
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_dataset(data: Dict, filepath: Path):
    """Save a dataset to JSON file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Saved {filepath}")


def pool_all_samples(datasets: List[Dict]) -> Dict[str, Dict[str, Set[str]]]:
    """
    Pool all samples from multiple datasets, deduplicating.
    Returns: {tool_name: {"benign": set(), "attack": set()}}
    """
    pooled = defaultdict(lambda: {"benign": set(), "attack": set()})

    for dataset in datasets:
        for tool, categories in dataset.items():
            if isinstance(categories, dict):
                for category in ["benign", "attack"]:
                    if category in categories:
                        for sample in categories[category]:
                            pooled[tool][category].add(sample)

    return pooled


def analyze_pool(pooled: Dict[str, Dict[str, Set[str]]]):
    """Print analysis of pooled data."""
    print("\n=== Pooled Data Analysis ===")
    print(f"{'Tool':<25} {'Benign':>10} {'Attack':>10} {'Total':>10} {'Ratio':>10}")
    print("-" * 70)

    total_benign = 0
    total_attack = 0

    for tool in sorted(pooled.keys()):
        benign_count = len(pooled[tool]["benign"])
        attack_count = len(pooled[tool]["attack"])
        total = benign_count + attack_count
        ratio = f"{benign_count}/{attack_count}" if attack_count > 0 else "N/A"

        print(f"{tool:<25} {benign_count:>10} {attack_count:>10} {total:>10} {ratio:>10}")
        total_benign += benign_count
        total_attack += attack_count

    print("-" * 70)
    print(f"{'TOTAL':<25} {total_benign:>10} {total_attack:>10} {total_benign + total_attack:>10}")
    print()


def split_samples_for_tool(
    benign_samples: List[str],
    attack_samples: List[str],
    train_benign_ratio: float,
    val_benign_ratio: float,
    test_benign_ratio: float
) -> Tuple[Dict, Dict, Dict]:
    """
    Split samples for a single tool into train/val/test with target ratios.

    For training (50/50): Use equal amounts of benign and attack
    For testing (90/10): Use 9x more benign than attack
    For validation (50/50): Use equal amounts of benign and attack

    Ensures each split has at least 1 sample of each class when available.
    """
    random.shuffle(benign_samples)
    random.shuffle(attack_samples)

    n_benign = len(benign_samples)
    n_attack = len(attack_samples)

    # First, distribute benign and attack samples proportionally to splits
    # Then adjust within each split to match target ratios as closely as possible

    # Split benign samples according to base split ratios
    train_benign_base = int(n_benign * TRAIN_RATIO)
    val_benign_base = int(n_benign * VAL_RATIO)
    test_benign_base = n_benign - train_benign_base - val_benign_base

    # Split attack samples according to base split ratios
    train_attack_base = int(n_attack * TRAIN_RATIO)
    val_attack_base = int(n_attack * VAL_RATIO)
    test_attack_base = n_attack - train_attack_base - val_attack_base

    # Ensure at least 1 sample per category per split when available
    if n_benign >= 3:
        train_benign_base = max(train_benign_base, 1)
        val_benign_base = max(val_benign_base, 1)
        test_benign_base = max(test_benign_base, 1)
        # Rebalance if we over-allocated
        while train_benign_base + val_benign_base + test_benign_base > n_benign:
            if test_benign_base > 1:
                test_benign_base -= 1
            elif train_benign_base > 1:
                train_benign_base -= 1
            elif val_benign_base > 1:
                val_benign_base -= 1
            else:
                break

    if n_attack >= 3:
        train_attack_base = max(train_attack_base, 1)
        val_attack_base = max(val_attack_base, 1)
        test_attack_base = max(test_attack_base, 1)
        # Rebalance if we over-allocated
        while train_attack_base + val_attack_base + test_attack_base > n_attack:
            if test_attack_base > 1:
                test_attack_base -= 1
            elif train_attack_base > 1:
                train_attack_base -= 1
            elif val_attack_base > 1:
                val_attack_base -= 1
            else:
                break

    # For training/validation (50/50 target), limit to min(benign, attack)
    train_min = min(train_benign_base, train_attack_base)
    train_benign_count = train_min if train_benign_base > 0 else 0
    train_attack_count = train_min if train_attack_base > 0 else 0
    # Use all available if one class is exhausted
    if train_benign_count == 0:
        train_attack_count = train_attack_base
    if train_attack_count == 0:
        train_benign_count = train_benign_base

    val_min = min(val_benign_base, val_attack_base)
    val_benign_count = val_min if val_benign_base > 0 else 0
    val_attack_count = val_min if val_attack_base > 0 else 0
    # Use all available if one class is exhausted
    if val_benign_count == 0:
        val_attack_count = val_attack_base
    if val_attack_count == 0:
        val_benign_count = val_benign_base

    # For test (90/10 target), we want many more benign than attack
    # First use the base attack count, then fill with remaining benign
    test_attack_count = test_attack_base

    # Calculate remaining benign after train/val allocation
    used_benign = train_benign_count + val_benign_count
    remaining_benign = n_benign - used_benign

    # For 90/10 ratio: benign should be ~9x attack
    # But we use all remaining benign samples to maximize test set realism
    test_benign_count = remaining_benign

    # Slice the samples
    benign_idx = 0
    attack_idx = 0

    train_benign = benign_samples[benign_idx:benign_idx + train_benign_count]
    benign_idx += train_benign_count

    val_benign = benign_samples[benign_idx:benign_idx + val_benign_count]
    benign_idx += val_benign_count

    test_benign = benign_samples[benign_idx:benign_idx + test_benign_count]

    train_attack = attack_samples[attack_idx:attack_idx + train_attack_count]
    attack_idx += train_attack_count

    val_attack = attack_samples[attack_idx:attack_idx + val_attack_count]
    attack_idx += val_attack_count

    test_attack = attack_samples[attack_idx:attack_idx + test_attack_count]

    train_data = {"benign": train_benign, "attack": train_attack}
    val_data = {"benign": val_benign, "attack": val_attack}
    test_data = {"benign": test_benign, "attack": test_attack}

    return train_data, val_data, test_data


def create_owasp_datasets(pooled: Dict[str, Dict[str, Set[str]]]) -> Tuple[Dict, Dict, Dict]:
    """
    Create OWASP-compliant train/val/test datasets from pooled samples.
    """
    train_dataset = {}
    val_dataset = {}
    test_dataset = {}

    for tool in sorted(pooled.keys()):
        benign_list = list(pooled[tool]["benign"])
        attack_list = list(pooled[tool]["attack"])

        if not benign_list and not attack_list:
            continue

        train_data, val_data, test_data = split_samples_for_tool(
            benign_list,
            attack_list,
            TRAIN_BENIGN_RATIO,
            VAL_BENIGN_RATIO,
            TEST_BENIGN_RATIO
        )

        # Only add tool if it has samples in the split
        if train_data["benign"] or train_data["attack"]:
            train_dataset[tool] = train_data
        if val_data["benign"] or val_data["attack"]:
            val_dataset[tool] = val_data
        if test_data["benign"] or test_data["attack"]:
            test_dataset[tool] = test_data

    return train_dataset, val_dataset, test_dataset


def verify_no_overlap(train: Dict, val: Dict, test: Dict) -> bool:
    """Verify there's no sample overlap between datasets."""
    print("\n=== Verifying No Overlap ===")

    overlaps_found = False

    for tool in set(train.keys()) | set(val.keys()) | set(test.keys()):
        for category in ["benign", "attack"]:
            train_samples = set(train.get(tool, {}).get(category, []))
            val_samples = set(val.get(tool, {}).get(category, []))
            test_samples = set(test.get(tool, {}).get(category, []))

            train_val_overlap = train_samples & val_samples
            train_test_overlap = train_samples & test_samples
            val_test_overlap = val_samples & test_samples

            if train_val_overlap:
                print(f"OVERLAP: {tool}/{category} - train/val: {len(train_val_overlap)} samples")
                overlaps_found = True
            if train_test_overlap:
                print(f"OVERLAP: {tool}/{category} - train/test: {len(train_test_overlap)} samples")
                overlaps_found = True
            if val_test_overlap:
                print(f"OVERLAP: {tool}/{category} - val/test: {len(val_test_overlap)} samples")
                overlaps_found = True

    if not overlaps_found:
        print("[OK] No overlaps found between datasets")

    return not overlaps_found


def print_dataset_stats(name: str, dataset: Dict, target_ratio: str):
    """Print statistics for a dataset."""
    print(f"\n=== {name} Dataset ({target_ratio} target) ===")
    print(f"{'Tool':<25} {'Benign':>10} {'Attack':>10} {'Total':>10} {'B/A Ratio':>12}")
    print("-" * 72)

    total_benign = 0
    total_attack = 0

    for tool in sorted(dataset.keys()):
        benign_count = len(dataset[tool].get("benign", []))
        attack_count = len(dataset[tool].get("attack", []))
        total = benign_count + attack_count

        if total > 0:
            ratio_pct = f"{benign_count/total*100:.0f}/{attack_count/total*100:.0f}"
        else:
            ratio_pct = "N/A"

        print(f"{tool:<25} {benign_count:>10} {attack_count:>10} {total:>10} {ratio_pct:>12}")
        total_benign += benign_count
        total_attack += attack_count

    total = total_benign + total_attack
    if total > 0:
        ratio_pct = f"{total_benign/total*100:.1f}/{total_attack/total*100:.1f}"
    else:
        ratio_pct = "N/A"

    print("-" * 72)
    print(f"{'TOTAL':<25} {total_benign:>10} {total_attack:>10} {total:>10} {ratio_pct:>12}")


def main():
    random.seed(RANDOM_SEED)

    print("Loading existing datasets...")

    # Load all existing datasets
    training = load_dataset(DATA_DIR / "training_dataset.json")
    test = load_dataset(DATA_DIR / "test_dataset.json")
    validation = load_dataset(DATA_DIR / "validation_dataset.json")

    print(f"Loaded training_dataset.json: {len(training)} tools")
    print(f"Loaded test_dataset.json: {len(test)} tools")
    print(f"Loaded validation_dataset.json: {len(validation)} tools")

    # Pool all samples
    print("\nPooling all samples...")
    pooled = pool_all_samples([training, test, validation])

    # Analyze pooled data
    analyze_pool(pooled)

    # Create OWASP-compliant datasets
    print("\nCreating OWASP-compliant datasets...")
    train_dataset, val_dataset, test_dataset = create_owasp_datasets(pooled)

    # Print statistics
    print_dataset_stats("Training", train_dataset, "50/50")
    print_dataset_stats("Validation", val_dataset, "50/50")
    print_dataset_stats("Test", test_dataset, "90/10")

    # Verify no overlap
    no_overlap = verify_no_overlap(train_dataset, val_dataset, test_dataset)

    if no_overlap:
        # Save datasets
        print("\nSaving OWASP-compliant datasets...")
        save_dataset(train_dataset, DATA_DIR / "owasp_training_dataset.json")
        save_dataset(val_dataset, DATA_DIR / "owasp_validation_dataset.json")
        save_dataset(test_dataset, DATA_DIR / "owasp_test_dataset.json")
        print("\n[OK] All datasets created successfully!")
    else:
        print("\n[ERROR] Overlaps detected - datasets not saved")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
