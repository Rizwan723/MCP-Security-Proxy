This implementation follows the JSON-RPC 2.0 standard.

Thesis "Vulnerability" Feature: I have included a flag SAFE_MODE.

If True (Production), it prevents path traversal using os.path.commonpath.

If False (Thesis Experiment Mode), it allows ../ paths.

Why: This allows you to prove that your MCP Bridge detects the attack before it even reaches this tool. If the Bridge works, the request never hits this vulnerable code.



How to Use This for Your Thesis

1. Baseline (No Attack):

. Client sends: read_file(path="user_docs/secret_plans.txt")

. Bridge detects: Distance < Threshold (Benign)

. Tool returns: "Confidential Project Report"

2. Attack (Path Traversal):

. Client sends:read_file(path=" .. / .. / .. /etc/thesis_secret")

. Scenario A (Bridge OFF): Tool returns "ROOT_PASSWORD=thesis_defense_fail"
(Bad!)
. Scenario B (Bridge ON): Bridge detects: Distance > Threshold
Security Policy Violation . The Tool never sees the request.

This setup gives you the perfect Control vs. Experiment data for your results section.

(Anomaly). Returns