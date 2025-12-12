#!/usr/bin/env python3
"""Analyze attack patterns in training vs test datasets to identify overlap."""

import json
import re
from pathlib import Path
from collections import defaultdict

def extract_attack_signatures(sample):
    """Extract attack signatures/techniques from a sample."""
    signatures = set()
    sample_lower = sample.lower()

    # Path traversal variants
    if '../' in sample or '..\\' in sample:
        signatures.add('path_traversal_dotdot')
    if '%2e' in sample_lower or '%2f' in sample_lower:
        signatures.add('path_traversal_urlencode')
    if '..../' in sample:
        signatures.add('path_traversal_double')

    # Command injection variants
    if '$(' in sample:
        signatures.add('cmd_injection_dollar_paren')
    if '`' in sample:
        signatures.add('cmd_injection_backtick')
    if '&&' in sample:
        signatures.add('cmd_injection_and')
    if '; ' in sample or sample.endswith(';'):
        signatures.add('cmd_injection_semicolon')
    if '|' in sample and 'nc' not in sample_lower:
        signatures.add('cmd_injection_pipe')
    if '${' in sample:
        signatures.add('cmd_injection_var_expansion')

    # SQL injection variants
    if "' or " in sample_lower or "or '" in sample_lower:
        signatures.add('sqli_or_bypass')
    if 'union' in sample_lower and 'select' in sample_lower:
        signatures.add('sqli_union')
    if '--' in sample:
        signatures.add('sqli_comment')
    if 'drop ' in sample_lower:
        signatures.add('sqli_drop')
    if 'exec' in sample_lower or 'xp_' in sample_lower:
        signatures.add('sqli_stored_proc')
    if 'sleep' in sample_lower or 'waitfor' in sample_lower:
        signatures.add('sqli_time_based')
    if 'information_schema' in sample_lower:
        signatures.add('sqli_schema_enum')
    if '/**/' in sample:
        signatures.add('sqli_comment_bypass')

    # XSS variants
    if '<script' in sample_lower:
        signatures.add('xss_script_tag')
    if 'onerror' in sample_lower or 'onload' in sample_lower:
        signatures.add('xss_event_handler')
    if 'javascript:' in sample_lower:
        signatures.add('xss_js_protocol')

    # SSRF variants
    if '127.0.0.1' in sample or 'localhost' in sample_lower:
        signatures.add('ssrf_localhost')
    if '169.254.169.254' in sample:
        signatures.add('ssrf_aws_metadata')
    if 'metadata.google' in sample_lower:
        signatures.add('ssrf_gcp_metadata')
    if '192.168.' in sample or '10.0.' in sample or '172.17.' in sample:
        signatures.add('ssrf_private_ip')
    if 'file://' in sample_lower:
        signatures.add('ssrf_file_protocol')
    if 'gopher://' in sample_lower:
        signatures.add('ssrf_gopher')
    if '::1' in sample or '::ffff' in sample:
        signatures.add('ssrf_ipv6')

    # Container/K8s specific
    if '/proc/' in sample:
        signatures.add('container_proc_access')
    if 'docker.sock' in sample:
        signatures.add('container_docker_sock')
    if 'kubernetes' in sample_lower or 'kubelet' in sample_lower:
        signatures.add('container_k8s')
    if '/hostfs' in sample or '/hostproc' in sample or '/host/' in sample:
        signatures.add('container_host_mount')
    if 'containerd' in sample_lower:
        signatures.add('container_containerd')
    if 'nsenter' in sample_lower:
        signatures.add('container_nsenter')
    if 'cgroup' in sample_lower:
        signatures.add('container_cgroup')

    # Template injection
    if '{{' in sample:
        signatures.add('template_injection')
    if 'constructor' in sample_lower:
        signatures.add('prototype_pollution')

    # Reverse shells
    if 'nc ' in sample_lower or 'netcat' in sample_lower:
        signatures.add('revshell_netcat')
    if '/bin/sh' in sample or '/bin/bash' in sample:
        signatures.add('revshell_shell')

    # Privilege escalation
    if '/etc/passwd' in sample:
        signatures.add('privesc_etc_passwd')
    if '/etc/shadow' in sample:
        signatures.add('privesc_etc_shadow')
    if 'sudoers' in sample:
        signatures.add('privesc_sudoers')
    if 'authorized_keys' in sample:
        signatures.add('privesc_ssh_keys')

    # ===== NOVEL ZERO-DAY ATTACK SIGNATURES =====

    # Unicode/homograph path traversal
    if '\\u002e' in sample or '\u002e' in sample:
        signatures.add('unicode_path_traversal')
    if '\\uff0e' in sample or '\uff0e' in sample:
        signatures.add('fullwidth_dot_traversal')

    # Windows reserved device names
    windows_reserved = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'LPT1', 'LPT2']
    if any(r in sample.upper() for r in windows_reserved):
        signatures.add('windows_reserved_names')

    # Header injection (CRLF)
    if '\\r\\n' in sample or '\r\n' in sample:
        signatures.add('header_injection_crlf')

    # Null byte injection
    if '\\u0000' in sample or '\x00' in sample or '%00' in sample:
        signatures.add('null_byte_injection')

    # PHP wrappers
    if 'php://' in sample_lower:
        signatures.add('php_wrapper')
    if 'phar://' in sample_lower:
        signatures.add('phar_wrapper')
    if 'zip://' in sample_lower:
        signatures.add('zip_wrapper')
    if 'data://' in sample_lower:
        signatures.add('data_uri_wrapper')

    # Prototype pollution
    if '__proto__' in sample:
        signatures.add('prototype_pollution_proto')

    # YAML deserialization
    if '!!python' in sample or '!!ruby' in sample:
        signatures.add('yaml_deserialization')

    # XXE attacks
    if '<!ENTITY' in sample or 'SYSTEM' in sample.upper() and 'file://' in sample_lower:
        signatures.add('xxe_attack')

    # NoSQL injection (MongoDB)
    if '$gt' in sample or '$ne' in sample or '$regex' in sample:
        signatures.add('nosql_injection_operators')
    if '$where' in sample:
        signatures.add('nosql_injection_where')
    if '$lookup' in sample or '$merge' in sample:
        signatures.add('nosql_injection_aggregation')

    # LDAP injection
    if '*)(uid=' in sample or ')(cn=' in sample:
        signatures.add('ldap_injection')

    # GraphQL injection
    if '__schema' in sample or '__type' in sample:
        signatures.add('graphql_introspection')

    # OGNL/Struts injection
    if 'ognl' in sample_lower or '#cmd' in sample:
        signatures.add('ognl_injection')

    # Log4Shell/JNDI
    if 'jndi:' in sample_lower:
        signatures.add('log4shell_jndi')

    # Alternative IP formats
    if re.search(r'http://\d{10,}', sample):  # Decimal IP
        signatures.add('decimal_ip_bypass')
    if re.search(r'http://0\d+\.', sample):  # Octal IP
        signatures.add('octal_ip_bypass')
    if re.search(r'http://0x[0-9a-f]+', sample_lower):  # Hex IP
        signatures.add('hex_ip_bypass')

    # DNS rebinding
    if '.nip.io' in sample or '.xip.io' in sample or '.sslip.io' in sample:
        signatures.add('dns_rebinding')

    # ReDoS (catastrophic backtracking)
    if re.search(r'\([^)]+\+\)\+', sample):
        signatures.add('redos_pattern')

    # Deserialization attacks
    if 'pickle' in sample_lower or 'marshal' in sample_lower:
        signatures.add('python_deserialization')

    # Alternative reverse shells
    if 'ruby -rsocket' in sample_lower:
        signatures.add('revshell_ruby')
    if 'php -r' in sample_lower:
        signatures.add('revshell_php')
    if 'awk' in sample_lower and 'inet' in sample_lower:
        signatures.add('revshell_awk')
    if 'lua' in sample_lower and 'socket' in sample_lower:
        signatures.add('revshell_lua')

    return signatures

def main():
    # Data directory is ../data relative to this tools/ directory
    data_dir = Path(__file__).parent.parent / 'data'

    with open(data_dir / 'training_dataset.json', 'r', encoding='utf-8') as f:
        train = json.load(f)
    with open(data_dir / 'test_dataset.json', 'r', encoding='utf-8') as f:
        test = json.load(f)

    # Collect all signatures from training
    train_signatures = defaultdict(int)
    train_malicious = []
    for tool, classes in train.items():
        for s in classes.get('malicious', []):
            train_malicious.append(s)
            for sig in extract_attack_signatures(s):
                train_signatures[sig] += 1

    # Collect all signatures from test
    test_signatures = defaultdict(int)
    test_malicious = []
    test_novel = []  # Samples with no training signatures

    for tool, classes in test.items():
        for s in classes.get('malicious', []):
            test_malicious.append(s)
            sigs = extract_attack_signatures(s)
            for sig in sigs:
                test_signatures[sig] += 1

            # Check if any signature is NOT in training
            novel_sigs = sigs - set(train_signatures.keys())
            if novel_sigs or not sigs:
                test_novel.append((s, sigs, novel_sigs))

    print("=" * 70)
    print("ATTACK SIGNATURE ANALYSIS")
    print("=" * 70)

    print(f"\nTraining malicious samples: {len(train_malicious)}")
    print(f"Test malicious samples: {len(test_malicious)}")

    print(f"\n--- Training Set Signatures ---")
    for sig, count in sorted(train_signatures.items(), key=lambda x: -x[1]):
        print(f"  {sig}: {count}")

    print(f"\n--- Test Set Signatures ---")
    for sig, count in sorted(test_signatures.items(), key=lambda x: -x[1]):
        in_train = "OK" if sig in train_signatures else "NEW"
        print(f"  [{in_train}] {sig}: {count}")

    # Find truly novel signatures in test
    novel_test_sigs = set(test_signatures.keys()) - set(train_signatures.keys())

    print(f"\n--- Novel Signatures in Test (not in training) ---")
    if novel_test_sigs:
        for sig in novel_test_sigs:
            print(f"  NEW: {sig}")
    else:
        print("  NONE - All test signatures appear in training!")

    print(f"\n--- Overlap Analysis ---")
    overlap = set(train_signatures.keys()) & set(test_signatures.keys())
    print(f"Signatures in both: {len(overlap)}")
    print(f"Signatures only in train: {len(set(train_signatures.keys()) - set(test_signatures.keys()))}")
    print(f"Signatures only in test: {len(novel_test_sigs)}")

    # Calculate overlap percentage
    if test_signatures:
        overlap_pct = len(overlap) / len(test_signatures) * 100
        print(f"\nTest signature overlap with training: {overlap_pct:.1f}%")
        if overlap_pct > 80:
            print("WARNING: High overlap - test set may not contain true zero-days!")

    print("\n" + "=" * 70)

if __name__ == '__main__':
    main()
