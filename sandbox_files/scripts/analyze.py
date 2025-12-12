#!/usr/bin/env python3
"""
Data analysis script for processing CSV files
"""
import csv
import json
from collections import defaultdict

def analyze_users(csv_path):
    """Analyze user data and generate statistics"""
    role_counts = defaultdict(int)
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            role_counts[row['role']] += 1
    
    return {
        'total_users': sum(role_counts.values()),
        'roles': dict(role_counts)
    }

if __name__ == '__main__':
    stats = analyze_users('/sandbox_files/data/users.csv')
    print(json.dumps(stats, indent=2))
