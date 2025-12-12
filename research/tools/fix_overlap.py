#!/usr/bin/env python3
"""Remove overlapping samples from test dataset."""

import json
from pathlib import Path

def main():
    # Data directory is ../data relative to this tools/ directory
    data_dir = Path(__file__).parent.parent / 'data'

    # Load datasets
    with open(data_dir / 'training_dataset.json', 'r', encoding='utf-8') as f:
        train = json.load(f)
    with open(data_dir / 'test_dataset.json', 'r', encoding='utf-8') as f:
        test = json.load(f)

    # Collect all training samples
    train_samples = set()
    for tool, classes in train.items():
        for cls, samples in classes.items():
            for s in samples:
                train_samples.add(s)

    print(f"Training samples: {len(train_samples)}")

    # Remove overlapping samples from test
    removed_count = 0
    for tool, classes in test.items():
        for cls, samples in list(classes.items()):
            original_len = len(samples)
            classes[cls] = [s for s in samples if s not in train_samples]
            removed_count += original_len - len(classes[cls])

    print(f"Removed {removed_count} overlapping samples from test set")

    # Save fixed test dataset
    with open(data_dir / 'test_dataset.json', 'w', encoding='utf-8') as f:
        json.dump(test, f, indent=2, ensure_ascii=False)

    print("Saved updated test_dataset.json")

    # Verify
    test_samples = set()
    test_stats = {'benign': 0, 'sensitive': 0, 'malicious': 0}
    for tool, classes in test.items():
        for cls, samples in classes.items():
            test_stats[cls] += len(samples)
            for s in samples:
                test_samples.add(s)

    overlap = train_samples & test_samples
    print(f"\nAfter fix:")
    print(f"  Test samples: {sum(test_stats.values())}")
    print(f"  Overlap: {len(overlap)}")

    if len(overlap) == 0:
        print("  [OK] No overlap!")
    else:
        print(f"  [WARNING] Still {len(overlap)} overlapping samples")

if __name__ == '__main__':
    main()
