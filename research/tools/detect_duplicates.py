#!/usr/bin/env python3
"""
Duplicate Detection Tool for Dataset JSON Files

Detects and optionally removes duplicate entries between dataset files.
Useful for ensuring test/validation datasets don't contain training samples.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple


def load_dataset(path: Path) -> Dict[str, Dict[str, List[str]]]:
    """Load a dataset JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_dataset(path: Path, data: Dict[str, Dict[str, List[str]]]) -> None:
    """Save a dataset JSON file with pretty formatting."""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def extract_all_entries(dataset: Dict[str, Dict[str, List[str]]]) -> Set[Tuple[str, str, str]]:
    """Extract all (tool, category, payload) tuples from a dataset."""
    entries = set()
    for tool, categories in dataset.items():
        for category, payloads in categories.items():
            for payload in payloads:
                entries.add((tool, category, payload))
    return entries


def extract_payloads_only(dataset: Dict[str, Dict[str, List[str]]]) -> Set[str]:
    """Extract all payload strings from a dataset (ignoring tool/category)."""
    payloads = set()
    for tool, categories in dataset.items():
        for category, payload_list in categories.items():
            for payload in payload_list:
                payloads.add(payload)
    return payloads


def find_duplicates(
    source: Dict[str, Dict[str, List[str]]],
    reference: Dict[str, Dict[str, List[str]]],
    match_tool: bool = True
) -> List[Tuple[str, str, str]]:
    """
    Find entries in source that also exist in reference.

    Args:
        source: Dataset to check for duplicates
        reference: Dataset to compare against
        match_tool: If True, match on (tool, category, payload).
                    If False, match only on payload string.

    Returns:
        List of (tool, category, payload) tuples that are duplicates
    """
    duplicates = []

    if match_tool:
        ref_entries = extract_all_entries(reference)
        for tool, categories in source.items():
            for category, payloads in categories.items():
                for payload in payloads:
                    if (tool, category, payload) in ref_entries:
                        duplicates.append((tool, category, payload))
    else:
        ref_payloads = extract_payloads_only(reference)
        for tool, categories in source.items():
            for category, payloads in categories.items():
                for payload in payloads:
                    if payload in ref_payloads:
                        duplicates.append((tool, category, payload))

    return duplicates


def remove_duplicates(
    dataset: Dict[str, Dict[str, List[str]]],
    duplicates: List[Tuple[str, str, str]]
) -> Tuple[Dict[str, Dict[str, List[str]]], int]:
    """
    Remove duplicate entries from a dataset.

    Returns:
        Tuple of (cleaned dataset, number of removed entries)
    """
    dup_set = set(duplicates)
    cleaned = {}
    removed_count = 0

    for tool, categories in dataset.items():
        cleaned[tool] = {}
        for category, payloads in categories.items():
            cleaned_payloads = []
            for payload in payloads:
                if (tool, category, payload) in dup_set:
                    removed_count += 1
                else:
                    cleaned_payloads.append(payload)
            if cleaned_payloads:
                cleaned[tool][category] = cleaned_payloads

        if not cleaned[tool]:
            del cleaned[tool]

    return cleaned, removed_count


def find_internal_duplicates(dataset: Dict[str, Dict[str, List[str]]]) -> Dict[str, List[Tuple[str, str, str]]]:
    """Find duplicate payloads within the same dataset."""
    seen = {}
    duplicates = {}

    for tool, categories in dataset.items():
        for category, payloads in categories.items():
            for payload in payloads:
                key = (tool, category, payload)
                if payload in seen:
                    orig_tool, orig_cat = seen[payload]
                    dup_key = f"{orig_tool}/{orig_cat}"
                    if dup_key not in duplicates:
                        duplicates[dup_key] = []
                    duplicates[dup_key].append((tool, category, payload))
                else:
                    seen[payload] = (tool, category)

    return duplicates


def main():
    parser = argparse.ArgumentParser(
        description='Detect and remove duplicates between dataset JSON files'
    )
    parser.add_argument(
        'source',
        type=Path,
        help='Source dataset file to check for duplicates'
    )
    parser.add_argument(
        'reference',
        type=Path,
        nargs='?',
        help='Reference dataset file to compare against (optional for internal duplicate check)'
    )
    parser.add_argument(
        '--delete',
        action='store_true',
        help='Delete duplicates from source file'
    )
    parser.add_argument(
        '--payload-only',
        action='store_true',
        help='Match duplicates by payload string only (ignore tool/category)'
    )
    parser.add_argument(
        '--internal',
        action='store_true',
        help='Check for duplicates within the source file itself'
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='Output file path (default: overwrite source when --delete is used)'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Show detailed duplicate information'
    )

    args = parser.parse_args()

    if not args.source.exists():
        print(f"Error: Source file not found: {args.source}")
        sys.exit(1)

    source_data = load_dataset(args.source)

    if args.internal:
        print(f"Checking for internal duplicates in: {args.source}")
        internal_dups = find_internal_duplicates(source_data)

        if internal_dups:
            total = sum(len(v) for v in internal_dups.values())
            print(f"\nFound {total} internal duplicate(s):")
            for orig, dups in internal_dups.items():
                print(f"\n  Original in {orig}:")
                for tool, cat, payload in dups:
                    preview = payload[:80] + "..." if len(payload) > 80 else payload
                    print(f"    - {tool}/{cat}: {preview}")
        else:
            print("No internal duplicates found.")
        return

    if not args.reference:
        print("Error: Reference file required (or use --internal for self-check)")
        sys.exit(1)

    if not args.reference.exists():
        print(f"Error: Reference file not found: {args.reference}")
        sys.exit(1)

    reference_data = load_dataset(args.reference)

    print(f"Source: {args.source}")
    print(f"Reference: {args.reference}")
    print(f"Match mode: {'payload-only' if args.payload_only else 'full (tool+category+payload)'}")

    duplicates = find_duplicates(
        source_data,
        reference_data,
        match_tool=not args.payload_only
    )

    if not duplicates:
        print("\nNo duplicates found.")
        return

    print(f"\nFound {len(duplicates)} duplicate(s):")

    by_tool = {}
    for tool, category, payload in duplicates:
        key = f"{tool}/{category}"
        if key not in by_tool:
            by_tool[key] = []
        by_tool[key].append(payload)

    for key, payloads in sorted(by_tool.items()):
        print(f"\n  {key}: {len(payloads)} duplicate(s)")
        if args.verbose:
            for payload in payloads[:5]:
                preview = payload[:80] + "..." if len(payload) > 80 else payload
                print(f"    - {preview}")
            if len(payloads) > 5:
                print(f"    ... and {len(payloads) - 5} more")

    if args.delete:
        cleaned_data, removed = remove_duplicates(source_data, duplicates)
        output_path = args.output if args.output else args.source
        save_dataset(output_path, cleaned_data)
        print(f"\nRemoved {removed} duplicate(s)")
        print(f"Saved cleaned dataset to: {output_path}")

        source_tools = len(source_data)
        cleaned_tools = len(cleaned_data)
        if source_tools != cleaned_tools:
            print(f"Note: {source_tools - cleaned_tools} tool(s) removed (became empty)")


if __name__ == '__main__':
    main()
