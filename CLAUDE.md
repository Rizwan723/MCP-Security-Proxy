# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **thesis research project** implementing a transparent security proxy for Model Context Protocol (MCP) using ensemble anomaly detection with DistilBERT embeddings and prototypical learning. The system validates all requests between Language Models and MCP tools using a **binary classification model** (Benign vs Attack).

**Core Architecture Pattern**: Transparent Security Proxy with Binary Classification

**Key Design Decisions**:
- **Binary Classification**: Simple, fast, and accurate - BENIGN (allow) vs ATTACK (block)
- **Fail-Safe Behavior**: Ambiguous cases default to ATTACK to minimize false negatives
- **Margin-Based Classification**: Benign requires clear majority (>10% margin) to allow request
- **Ensemble Approach**: Multiple detectors with weighted voting for robust detection

**MCP Compatibility**: The bridge is **protocol-compliant** and works out-of-the-box with any standard MCP server that implements:
- `tools/list` - Tool discovery endpoint
- `tools/call` - Tool execution endpoint
- JSON-RPC 2.0 transport

This means you can plug in existing open-source MCP servers without modification. The bridge acts as a transparent proxy, forwarding validated requests to upstream MCP servers.

## Essential Commands

### Docker Operations
```bash
# Start all services (required for development)
docker compose up -d --build

# View bridge logs (most useful for debugging)
docker compose logs -f mcp-bridge

# Restart bridge after code changes
docker compose restart mcp-bridge

# Stop all services
docker compose down
```

### Testing
```bash
# Interactive client testing
docker exec -it mcp-client python agent.py

# Manual tool testing (direct JSON-RPC)
docker exec -it mcp-client python test_tools.py

# Load/traffic generation
docker exec -it mcp-client python traffic_generator.py --samples 100 --ratio 0.3 --concurrency 10

# Latency benchmarking
docker exec -it mcp-client python latency_test.py
```

### Health Checks
```bash
# Check bridge status
curl http://localhost:8000/health

# Check local LLM service
curl http://localhost:8080/health
```

### Research/Model Training
```bash
# Access Jupyter notebooks for model evaluation
cd research/notebooks
jupyter notebook

# Scientific Evaluation Notebooks:
# - models_evaluation.ipynb: ROC curves, confusion matrices, precision-recall, per-detector analysis
# - bridge_evaluation.ipynb: Latency profiling, throughput metrics, SLA compliance
# - detector_analysis.ipynb: Deep-dive into individual detector performance

# Standalone model training (semantic + statistical)
python research/tools/train_models.py

# Train with MAML meta-learning
python research/tools/train_models.py --maml --maml-epochs 100
```

## Architecture Overview

### Network Isolation (Critical Security Boundary)
- **mcp-public**: External access (Client <-> Bridge, Bridge <-> LLM)
- **mcp-secure**: Internal only (Bridge <-> Tools). Tools have NO internet access (`internal: true` in docker compose)

### Component Responsibilities

**mcp_bridge/** - FastAPI security proxy (port 8000)
- **Transparent MCP proxy**: Intercepts and forwards JSON-RPC 2.0 requests
- **Dynamic tool discovery**: Queries all configured MCP servers via `tools/list` on startup
- **Security inspection**: Runs `BinaryMCPDetector` for binary classification (benign vs attack)
- **Request routing**: Maintains dynamic routing table (tool_name → server_url)
- **Connection pooling**: Async HTTP client pool via `RequestForwarder`
- **MCP Protocol Handlers**: Full MCP 2024-11-05 support including `initialize`, `ping`, `tools/list`, `resources/list`, `prompts/list`

**mcp_tools/** - Example MCP servers (these can be replaced with any standard MCP server)
- **filesystem**: File operations (read, write, list, search)
- **sqlite**: Database queries (SELECT, INSERT, list_tables, describe_table)
- **time**: Timezone operations (get_current_time, convert_time)
- **fetch**: URL fetching (fetch_url, fetch_html, check_url)
- **memory**: Knowledge graph (create_entity, search_entities, add_relation)
- All implement MCP 2024-11-05 spec with `tools/list`, `tools/call`, `isError` field
- Run on isolated `mcp-secure` network (no internet access)

**llm_service/** - Local LLM inference (llama.cpp) (port 8080)
- Hosts quantized models (Llama-2, Llama-3, Mistral)
- GPU-accelerated when NVIDIA drivers available
- Not required for bridge operation (bridge works with any LLM)

**llm_cloud_service/** - Cloud LLM wrapper (port 8081)
- OpenAI/Gemini API adapter
- Provides unified /v1/chat/completions interface
- Not required for bridge operation (bridge works with any LLM)

**research/** - Thesis data and notebooks
- data/: Datasets (training_dataset.json, test_dataset.json, validation_dataset.json)
- trained_models/: Pre-trained detectors (semantic_model.pt, statistical_model.pt, maml_model.pt)
- notebooks/: Scientific evaluation
  - models_evaluation.ipynb: ROC curves, confusion matrices, precision-recall
  - bridge_evaluation.ipynb: Latency profiling, throughput metrics, SLA compliance
  - detector_analysis.ipynb: Per-detector deep-dive analysis
- evaluation_results/: Exported CSVs and JSON summaries from notebooks
- tools/: Research utility scripts
  - train_models.py: Standalone training script (supports --maml flag for MAML training)
  - analyze_patterns.py: Attack signature analysis for training/test overlap detection
  - verify_datasets.py: Dataset integrity and data leakage checker
  - fix_overlap.py: Remove overlapping samples from test dataset
  - add_payloads.py: Add real-world attack payloads, convert to binary classification format
  - balance_datasets.py: Balance dataset ratios (benign/attack) with synthetic samples

**client/** - Testing utilities
- agent.py: Interactive chat interface with tool calling
- traffic_generator.py: Load testing and attack simulation
- test_tools.py: Direct JSON-RPC validation
- latency_test.py: Performance benchmarking for bridge latency

## Detection System Architecture

### Binary Security Model

The detector classifies requests into two categories:

1. **BENIGN** (Allow) - Safe requests matching known good patterns
   - Example: `read_file("docs/notes.txt")`, `SELECT * FROM products`
   - Definition: Matches known good patterns, uses standard arguments, aligns with context

2. **ATTACK** (Block) - All threat types merged into single category
   - **Injection attacks**: SQL injection, command injection, XSS
   - **Path traversal**: `../../../etc/passwd`, `..\..\Windows\System32`
   - **Sensitive access**: `.env` files, credentials, API keys
   - **Anomalous patterns**: Statistically improbable requests
   - **Policy violations**: Bulk data access, destructive operations

### Detection Pipeline (Ensemble Approach)

All detectors contribute to a weighted ensemble vote:

1. **RuleBasedDetector** ([mcp_bridge/src/core/detectors/rule_based.py](mcp_bridge/src/core/detectors/rule_based.py))
   - Fastest, high precision for known attacks
   - Regex patterns for path traversal, SQL injection, command injection, SSRF, XSS
   - Returns ATTACK immediately on pattern match with high confidence
   - Defers to other detectors when no patterns match

2. **StatisticalFeatureDetector** ([mcp_bridge/src/core/detectors/statistical.py](mcp_bridge/src/core/detectors/statistical.py))
   - Rich feature extraction: length, entropy, special char ratios, suspicious pattern density
   - Mahalanobis distance-based anomaly detection
   - Good for detecting novel attacks that don't match known patterns
   - Binary classification with fail-safe behavior

3. **MAMLDetector** ([mcp_bridge/src/core/detectors/maml.py](mcp_bridge/src/core/detectors/maml.py)) - Optional
   - Model-Agnostic Meta-Learning for few-shot adaptation
   - DistilBERT embeddings with 2-class neural classifier
   - **Few-Shot Learning**: Adapts to new tools with 5-10 examples per class
   - **Fast Adaptation**: 5 gradient steps for task-specific fine-tuning
   - Enable with `MAML_ENABLED=true` environment variable

4. **SemanticDetector** ([mcp_bridge/src/core/detectors/semantic.py](mcp_bridge/src/core/detectors/semantic.py))
   - DistilBERT embeddings (768-dim) with security feature augmentation
   - Prototypical learning with cosine similarity
   - Margin-based classification: benign must be 10% closer than attack
   - Out-of-distribution detection for unknown attack patterns

### Ensemble Strategy (Dynamic Weighted Voting)

The `BinaryMCPDetector` uses a **dynamic weighted ensemble** approach:

**Default Weights** (based on empirical AUC performance):
- Rule-Based: 0.40 (high precision, high weight)
- Semantic: 0.35 (best generalization)
- Statistical: 0.15 (anomaly detection)
- MAML: 0.10 (meta-learning, if enabled)

**Features**:
- **Confidence Calibration**: Temperature scaling for each detector (Rule: 1.0, Semantic: 1.1, Statistical: 1.3)
- **Fail-Safe Tie-Breaking**: When margin < 10%, defaults to ATTACK
- **Dynamic Weight Adjustment**: Weights adjust automatically based on detector agreement over last 1000 predictions
- **Performance Tracking**: Monitors detector predictions for reliability scoring

### Model Lifecycle

**Training** ([mcp_bridge/src/main.py](mcp_bridge/src/main.py))
- On startup, attempts to load pre-trained models from `research/trained_models/`
- If models not found, trains from `research/data/training_dataset.json`
- Automatically saves newly trained models for future use

**Retraining Process**:
```bash
# 1. Delete existing models
rm research/trained_models/semantic_model.pt
rm research/trained_models/statistical_model.pt
rm research/trained_models/maml_model.pt  # Optional

# 2. Restart bridge (will retrain from training_dataset.json)
docker compose restart mcp-bridge

# 3. Train MAML model separately (optional, requires more time)
python research/tools/train_models.py --maml --maml-epochs 100
```

### Thresholding (Sigma Rule)

Detection sensitivity controlled by `DETECTOR_SIGMA` (default: 3.0)
- Formula: `threshold = mean(distances) + sigma * std(distances)`
- Lower sigma = stricter detection (more false positives)
- Higher sigma = lenient detection (more false negatives)
- Standard three-sigma rule (99.7% of benign samples within threshold)

## Key Code Locations

### Request Flow
1. Client sends JSON-RPC to [mcp_bridge/src/main.py:241](mcp_bridge/src/main.py#L241) `/jsonrpc`
2. MCP protocol methods handled first (initialize, ping, tools/list, etc.)
3. Payload extracted and flattened for tools/call
4. Detection runs in threadpool via `BinaryMCPDetector.predict()`
5. If blocked, returns JSON-RPC error with class/confidence
6. If allowed, forwarded via [mcp_bridge/src/services/forwarder.py](mcp_bridge/src/services/forwarder.py)

### MCP Protocol Handlers
- `initialize`: Negotiates capabilities and protocol version
- `ping`: Health check
- `tools/list`: Aggregates tools from upstream servers with pagination
- `resources/list` and `prompts/list`: Placeholder endpoints
- Root path `/` alias for JSON-RPC endpoint

### Tool Discovery (MCP Standard Protocol)
- Dynamic discovery at startup [mcp_bridge/src/services/forwarder.py](mcp_bridge/src/services/forwarder.py)
- Queries each server in `settings.mcp_servers` for `tools/list` (MCP standard method)
- Populates routing table: `tool_name -> server_url`
- Periodic rediscovery every 60 seconds to detect new tools
- Fallback to legacy hardcoded mapping if discovery fails (for non-compliant servers)

### Detector Facade
The main detector facade is [mcp_bridge/src/core/detector.py](mcp_bridge/src/core/detector.py):
- `BinaryMCPDetector`: Singleton facade for all detectors
- `fit()`: Train detectors on labeled samples (benign + attack)
- `predict()`: Ensemble prediction with weighted voting
- `save_models()` / `load_models()`: Persistence with metadata
- `get_model_info()`: Introspection for debugging
- `provide_feedback()`: Supervised feedback for weight adjustment
- `get_performance_stats()`: Ensemble performance metrics

## Development Patterns

### Async/FastAPI
- Bridge is high-throughput; use `async def` for all handlers
- CPU-bound operations (ML inference) run in threadpool: `await run_in_threadpool(detector.predict, ...)`
- Tool communication uses `httpx.AsyncClient` with connection pooling

### Integrating Existing MCP Servers

The bridge works with **any standard MCP server** out of the box. No code changes needed to existing MCP servers.

**Option 1: Using Existing Open-Source MCP Servers**

1. Add server to `docker compose.yml`:
   ```yaml
   services:
     mcp-github:
       image: ghcr.io/example/mcp-github:latest
       networks:
         - mcp-secure
       environment:
         - GITHUB_TOKEN=${GITHUB_TOKEN}
   ```

2. Register in `mcp_bridge/src/config.py` or via `MCP_SERVERS` env var

3. Generate training data for security detection (optional but recommended):
   ```json
   {
     "github_create_issue": {
       "benign": ["{\"repo\": \"myorg/myrepo\", \"title\": \"Bug report\"}", ...],
       "attack": ["{\"repo\": \"../../etc/passwd\", \"title\": \"$(rm -rf)\"}", ...]
     }
   }
   ```

4. Restart bridge - it will auto-discover tools via `tools/list`

**Option 2: Creating New MCP-Compatible Tools**

If building a new MCP server, follow the MCP specification:

1. Implement JSON-RPC 2.0 endpoint (POST `/` or `/jsonrpc`)
2. Support `tools/list` method
3. Support `tools/call` method
4. Add to `docker compose.yml` and `mcp_servers` list

See [mcp_tools/time/server.py](mcp_tools/time/server.py) for a reference implementation.

### Logging and Auditing
- Runtime audit logs: Written by [mcp_bridge/src/core/utils.py](mcp_bridge/src/core/utils.py) `log_thesis_data()`
- Format: JSONL with request_id, tool, payload, classification, allowed, confidence
- Location: Configured via `AUDIT_LOG_FILE` env var

## Environment Variables

**Critical Settings** (set in .env or docker compose.yml):

```env
# Detection Sensitivity
DETECTOR_SIGMA=3.0

# LLM Selection
LLM_MODEL_PATH=/app/models/llama-2-7b-chat.Q4_K_M.gguf
LLM_PROVIDER=gemini  # or 'openai' for cloud

# Security
SAFE_MODE=true  # Enable tool-level validation
LOG_LEVEL=INFO

# Model Paths
RESEARCH_DATA_PATH=/app/research_data
SEMANTIC_MODEL_PATH=/app/trained_models/semantic_model.pt
STATISTICAL_MODEL_PATH=/app/trained_models/statistical_model.pt
MAML_MODEL_PATH=/app/trained_models/maml_model.pt

# MAML Configuration (optional)
MAML_ENABLED=false              # Enable MAML detector in ensemble
MAML_META_LR=0.001              # Meta-learning rate (outer loop)
MAML_INNER_LR=0.01              # Task adaptation rate (inner loop)
MAML_ADAPTATION_STEPS=5         # Gradient steps for adaptation
MAML_FIRST_ORDER=true           # Use first-order MAML (faster)
MAML_SHOTS=5                    # Examples per class for adaptation
MAML_HIDDEN_DIM=256             # Classifier hidden layer size
MAML_CONFIDENCE_THRESHOLD=0.6   # Min confidence for benign classification
MAML_NUM_META_EPOCHS=100        # Meta-training epochs
```

## Important Constraints

1. **MCP Protocol Compliance**: The bridge is a **transparent proxy**. It must not break MCP protocol compatibility. All standard JSON-RPC 2.0 requests should pass through unmodified (except when blocked by security).

2. **Network Isolation is Sacred**: Tools on `mcp-secure` network must NEVER have internet access. Verify `internal: true` in docker compose.yml for security network. This is defense-in-depth.

3. **Binary Classification Model**: The system uses a 2-class security model:
   - **BENIGN**: Safe requests (allow)
   - **ATTACK**: All threat types merged (block)

4. **Prototypical Learning**: Each tool has separate prototypes for each class. Tools without training data will default-deny all requests (zero-trust). This means new tools need training data to be usable.

5. **Async Patterns**: Never run blocking operations (model inference, file I/O) in FastAPI handlers without threadpool/async wrapper. The bridge is high-throughput.

6. **Singleton Detector**: `BinaryMCPDetector` uses singleton pattern. Multiple instances would waste memory loading models multiple times.

7. **Training Data Format**: Tool-keyed dict with "benign" and "attack" keys. Each value is a list of JSON strings (serialized arguments).

## Research Context

This is a master's thesis project studying ML-based security for LLM tool use. Key metrics:
- **Latency**: < 100ms per request (bridge overhead)
- **Detection Accuracy**: > 95% AUROC
- **False Positive Rate**: < 5%

All experiments and evaluations are in `research/notebooks/`. The detector design prioritizes **scientific reproducibility** over production hardening.

## MCP Ecosystem Integration

**Compatibility Statement**: This bridge is designed to be a drop-in security layer for existing MCP deployments.

**Works with**:
- Official Anthropic MCP servers
- Community MCP servers (as long as they follow JSON-RPC 2.0 + `tools/list`/`tools/call`)
- Custom MCP implementations

**Does NOT require**:
- Modifying existing MCP server code
- Specific frameworks (FastAPI, Flask, etc. all work as long as JSON-RPC 2.0 compliant)
- Specific transport (HTTP POST with JSON body is all that's needed)

**Bridge as a Service**: You can point the bridge at remote MCP servers (not just local Docker containers). Just ensure network connectivity and update `mcp_servers` URLs accordingly. The `mcp-secure` network isolation is optional but recommended for defense-in-depth.

## Troubleshooting

### Common Issues

**1. Bridge fails to start / "No training data found"**
```bash
# Check if training data exists
ls research/data/training_dataset.json

# If missing, the detector runs in ZERO-SHOT mode (high false positives)
# Generate training data or copy from backup
```

**2. Tools not discovered**
```bash
# Check tool container status
docker compose ps

# View discovery logs
docker compose logs mcp-bridge | grep -i "discovery\|registered"

# Manually test tool discovery
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

**3. All requests being blocked (high false positives)**
```bash
# Check detector sigma (lower = stricter)
echo $DETECTOR_SIGMA  # Default: 3.0

# Try increasing sigma for lenient detection
DETECTOR_SIGMA=4.0 docker compose up -d mcp-bridge

# Check if models are loaded
docker compose logs mcp-bridge | grep -i "model loaded"
```

**4. GPU not detected for LLM service**
```bash
# Check NVIDIA driver
nvidia-smi

# Ensure Docker has GPU access
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi

# Check container GPU allocation
docker inspect custom-llm | grep -i gpu
```

**5. Model retraining after dataset changes**
```bash
# Delete cached models to force retraining
rm research/trained_models/semantic_model.pt
rm research/trained_models/statistical_model.pt

# Restart bridge
docker compose restart mcp-bridge
```

### Debugging Commands

```bash
# View real-time bridge logs
docker compose logs -f mcp-bridge

# Check health of all services
docker compose ps

# Test MCP initialize handshake
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"clientInfo":{"name":"debug","version":"1.0"}},"id":1}'

# Test tool call (should be blocked if attack detected)
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../etc/passwd"}},"id":1}'

# View audit logs
tail -f research/data/runtime_audit.jsonl
```

## FAQ

**Q: How do I add a new MCP server?**
A: Add the server URL to the `MCP_SERVERS` environment variable (comma-separated) in docker compose.yml, then restart the bridge. It will auto-discover tools via `tools/list`.

**Q: How do I train on new tools?**
A: Add training samples to `research/data/training_dataset.json` following the format:
```json
{
  "tool_name": {
    "benign": ["safe example 1", "safe example 2"],
    "attack": ["attack pattern example 1", "attack pattern example 2"]
  }
}
```
Then delete cached models and restart the bridge.

**Q: Why is MAML disabled by default?**
A: MAML requires additional meta-training time and computational resources. It's most useful for few-shot adaptation to new tools. Enable with `MAML_ENABLED=true` if you need rapid adaptation to new tool types.

**Q: How do I lower false positives?**
A: Increase `DETECTOR_SIGMA` (default: 3.0). Higher values = more lenient. Also ensure you have sufficient benign training samples for each tool.

**Q: How do I get stricter security (lower false negatives)?**
A: Decrease `DETECTOR_SIGMA`. Also consider enabling MAML for better generalization. The system uses fail-safe behavior for ambiguous cases.

**Q: Can I use this with Claude Desktop or other MCP clients?**
A: Yes! Point your MCP client to `http://localhost:8000` (or the bridge URL). The bridge is fully MCP 2024-11-05 compliant.

**Q: How do I provide feedback to improve detection?**
A: Use the `provide_feedback()` method on `BinaryMCPDetector` to label misclassified requests. The system will automatically adjust weights after 50+ labeled samples.

**Q: Why binary classification instead of multi-class?**
A: Binary classification (benign vs attack) is simpler, faster, and more accurate for security applications. It eliminates ambiguity between threat categories and provides clear allow/block decisions. All threat types (injections, traversals, anomalies, policy violations) are merged into a single "attack" class.
