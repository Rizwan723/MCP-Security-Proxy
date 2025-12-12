#!/usr/bin/env python3
"""Verify dataset integrity and check for data leakage."""

import json
from pathlib import Path

def main():
    # Load datasets - data directory is ../data relative to this tools/ directory
    data_dir = Path(__file__).parent.parent / 'data'
    with open(data_dir / 'training_dataset.json', 'r', encoding='utf-8') as f:
        train = json.load(f)
    with open(data_dir / 'test_dataset.json', 'r', encoding='utf-8') as f:
        test = json.load(f)

    # Collect all samples
    train_samples = set()
    test_samples = set()
    # Support both old (benign/sensitive/malicious) and new (benign/attack) formats
    train_stats = {'benign': 0, 'attack': 0}
    test_stats = {'benign': 0, 'attack': 0}

    for tool, classes in train.items():
        for cls, samples in classes.items():
            train_stats[cls] += len(samples)
            for s in samples:
                train_samples.add(s)

    for tool, classes in test.items():
        for cls, samples in classes.items():
            test_stats[cls] += len(samples)
            for s in samples:
                test_samples.add(s)

    # Check overlap
    overlap = train_samples & test_samples

    print('=' * 60)
    print('DATASET STATISTICS')
    print('=' * 60)

    print(f"\nTraining Dataset:")
    total_train = sum(train_stats.values())
    print(f"  Total: {total_train} samples")
    print(f"  - Benign: {train_stats['benign']:4d} ({train_stats['benign']/total_train*100:.1f}%)")
    print(f"  - Attack: {train_stats['attack']:4d} ({train_stats['attack']/total_train*100:.1f}%)")
    print(f"  - Ratio (benign:attack): 1:{train_stats['attack']/max(train_stats['benign'],1):.2f}")
    print(f"  - Tools: {len(train)}")

    print(f"\nTest Dataset:")
    total_test = sum(test_stats.values())
    print(f"  Total: {total_test} samples")
    print(f"  - Benign: {test_stats['benign']:4d} ({test_stats['benign']/total_test*100:.1f}%)")
    print(f"  - Attack: {test_stats['attack']:4d} ({test_stats['attack']/total_test*100:.1f}%)")
    print(f"  - Ratio (benign:attack): 1:{test_stats['attack']/max(test_stats['benign'],1):.2f}")
    print(f"  - Tools: {len(test)}")

    print(f"\nData Leakage Check:")
    print(f"  Overlapping samples: {len(overlap)}")
    if len(overlap) == 0:
        print('  [OK] NO DATA LEAKAGE DETECTED')
    else:
        print('  [WARNING] Data leakage detected!')
        print(f'    First 5 overlapping samples:')
        for s in list(overlap)[:5]:
            display = s[:60] + '...' if len(s) > 60 else s
            print(f'      {display}')

    # Attack type breakdown for malicious
    print(f"\nAttack Categories in Malicious Samples:")

    attack_patterns = {
        'Path Traversal': ['../', '..\\\\', '%2e%2e', '....//'],
        'Command Injection': ['$(', '&&', '; ', '\\n'],
        'SQL Injection': ['OR ', 'UNION', 'DROP', '--', "' OR", 'EXEC', 'DELETE', 'TRUNCATE'],
        'XSS': ['<script', 'onerror', 'javascript:', '<img'],
        'SSRF': ['localhost', '127.0.0.1', '169.254.169.254', 'metadata.google', 'file://', 'gopher://'],
        'Container Escape': ['/proc/1/', 'docker.sock', '/hostfs', '/hostproc', 'kubernetes', 'containerd', 'nsenter', 'cgroup', '/host/', 'kubelet'],
        'Template Injection': ['{{', '${', 'constructor'],
        # Novel zero-day categories
        'Unicode Bypass': ['\\u002e', '\\uff0e', '\u002e', '\uff0e'],
        'Windows Device': ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1'],
        'Null Byte': ['\\u0000', '%00', '\x00'],
        'PHP Wrapper': ['php://', 'phar://', 'zip://', 'data://'],
        'Prototype Pollution': ['__proto__'],
        'Deserialization': ['!!python', '!!ruby', 'pickle', 'marshal'],
        'NoSQL Injection': ['$gt', '$ne', '$regex', '$where', '$lookup'],
        'LDAP Injection': ['*)(uid=', ')(cn='],
        'GraphQL Injection': ['__schema', '__type'],
        'OGNL Injection': ['ognl', '#cmd'],
        'Log4Shell/JNDI': ['jndi:'],
        'DNS Rebinding': ['.nip.io', '.xip.io', '.sslip.io'],
        'IP Format Bypass': ['2852039166', '017700000001', '0x7f000001'],
        'Header Injection': ['\\r\\n', '\r\n'],
    }

    def categorize_attack(sample):
        categories = []
        for cat, patterns in attack_patterns.items():
            if any(p.lower() in sample.lower() for p in patterns):
                categories.append(cat)
        return categories if categories else ['Other']

    train_attack_cats = {}
    test_attack_cats = {}

    for tool, classes in train.items():
        # Support both 'malicious' (old format) and 'attack' (new format)
        attack_samples = classes.get('malicious', []) + classes.get('attack', [])
        for s in attack_samples:
            for cat in categorize_attack(s):
                train_attack_cats[cat] = train_attack_cats.get(cat, 0) + 1

    for tool, classes in test.items():
        attack_samples = classes.get('malicious', []) + classes.get('attack', [])
        for s in attack_samples:
            for cat in categorize_attack(s):
                test_attack_cats[cat] = test_attack_cats.get(cat, 0) + 1

    print(f"\n  Training Set Attack Distribution:")
    for cat, count in sorted(train_attack_cats.items(), key=lambda x: -x[1]):
        print(f"    - {cat}: {count}")

    print(f"\n  Test Set Attack Distribution:")
    for cat, count in sorted(test_attack_cats.items(), key=lambda x: -x[1]):
        print(f"    - {cat}: {count}")

    print('\n' + '=' * 60)

    return len(overlap) == 0

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
