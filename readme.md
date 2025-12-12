## Project Overview

This is my **thesis research project** implementing a transparent security proxy for the Model Context Protocol (MCP) using ensemble anomaly detection with DistilBERT embeddings and prototypical learning. The system validates all requests between Language Models and MCP tools using **binary classification** (Benign vs Attack).

**Core Architecture**: Transparent Security Proxy with Binary Classification

**Key Design Decisions**:
- **Binary Classification**: BENIGN (allow) vs ATTACK (block) for simplicity and accuracy
- **Fail-Safe Behavior**: Ambiguous cases default to ATTACK to minimize false negatives
- **Margin-Based Classification**: Benign requires clear margin to allow request
- **Ensemble Approach**: Multiple detectors with weighted voting for robust detection
- **MCP Protocol Compliance**: Transparent proxy compatible with any standard MCP server

## Essential Commands

### Docker Operations
```bash
# Start all services
docker compose up -d --build

# View bridge logs (primary debugging)
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

# Direct tool testing (JSON-RPC)
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
# Standalone model training
python research/tools/train_models.py

# Train with MAML meta-learning
python research/tools/train_models.py --maml --maml-epochs 100

# Access Jupyter notebooks
cd research/notebooks && jupyter notebook
```

## Architecture Overview

### Network Topology

- **mcp-public**: External access 
- **mcp-secure**: Internal only (`internal: true`). Tools have NO internet access.

### Component Responsibilities

**mcp_bridge/** - FastAPI security proxy (port 8000)
- Main entry point: `mcp_bridge/src/main.py`
- Configuration: `mcp_bridge/src/config.py`
- Transparent MCP proxy intercepting JSON-RPC 2.0 requests
- Dynamic tool discovery via `tools/list` on configured MCP servers
- Security inspection using `BinaryMCPDetector` ensemble
- Request routing via dynamic `tool_name → server_url` mapping
- MCP 2024-11-05 protocol support (`initialize`, `ping`, `tools/list`, `resources/list`, `prompts/list`)

**mcp_tools/** - Example MCP servers (can be replaced with any MCP-compliant server)
- `filesystem/server.py`: File operations (read_file, write_file, list_directory)
- `sqlite/server.py`: Database queries (read_query, write_query, list_tables, describe_table)
- `time/server.py`: Timezone operations (get_current_time, convert_time)
- `fetch/server.py`: URL fetching
- `memory/server.py`: Knowledge graph operations
- All implement MCP 2024-11-05 spec with `tools/list`, `tools/call`, `isError` field

**llm_service/** - Local LLM inference (port 8080)
- Uses llama-cpp-python with GGUF models
- GPU-accelerated when NVIDIA drivers available
- OpenAI-compatible `/v1/chat/completions` endpoint

**llm_cloud_service/** - Cloud LLM wrapper (port 8081)
- OpenAI/Gemini API adapter
- Unified `/v1/chat/completions` interface

**client/** - Testing utilities
- `agent.py`: Interactive chat with tool calling
- `traffic_generator.py`: Load testing and attack simulation
- `test_tools.py`: Direct JSON-RPC validation
- `latency_test.py`: Performance benchmarking

**research/** - Thesis data and analysis
- `data/`: Datasets (training_dataset.json, test_dataset.json, validation_dataset.json)
- `trained_models/`: Pre-trained detectors (semantic_model.pt, statistical_model.pt, maml_model.pt)
- `notebooks/`: Scientific evaluation (model_comparisons.ipynb, semantic_evaluation.ipynb, etc.)
- `tools/`: Research utilities (train_models.py, verify_datasets.py, etc.)

## Detection System Architecture

### Binary Security Model

Two classes:
1. **BENIGN** (Allow) - Safe requests matching known good patterns
2. **ATTACK** (Block) - All threat types: injections, traversals, anomalies, policy violations

### Detection Pipeline

The `BinaryMCPDetector` (`mcp_bridge/src/core/detector.py`) coordinates these detectors:

1. **RuleBasedDetector** (`mcp_bridge/src/core/detectors/rule_based.py`)
   - Regex patterns for known attacks (path traversal, SQL injection, command injection, SSRF, XSS)
   - High precision, returns immediately on pattern match
   - Returns `None` to defer to other detectors if no match

2. **StatisticalFeatureDetector** (`mcp_bridge/src/core/detectors/statistical.py`)
   - Feature extraction: length, entropy, special char ratios, suspicious pattern density
   - Mahalanobis distance with pooled covariance
   - Supports LDA (homoscedastic) and QDA (heteroscedastic) modes
   - Data-driven margin thresholds

3. **SemanticDetector** (`mcp_bridge/src/core/detectors/semantic.py`)
   - DistilBERT embeddings (768-dim) with security feature augmentation
   - Prototypical learning with cosine similarity
   - Data-driven margin-based classification
   - Out-of-distribution detection

4. **MAMLDetector** (`mcp_bridge/src/core/detectors/maml.py`) - Optional
   - Model-Agnostic Meta-Learning for few-shot adaptation
   - Enable with `MAML_ENABLED=true`

### Ensemble Strategy

**Default Weights** (empirically tuneable):
- Rule-Based: 0.40 (high precision)
- Semantic: 0.35 (best generalization)
- Statistical: 0.15 (anomaly detection)
- MAML: 0.10 (if enabled)

**Features**:
- Platt scaling / temperature calibration for confidence scores
- Fail-safe tie-breaking: margin < 10% defaults to ATTACK
- Weight adjustment via `provide_feedback()` with labeled samples

## Key Code Locations

### Request Flow
1. Request arrives at `mcp_bridge/src/main.py:243` `/jsonrpc` endpoint
2. MCP protocol methods handled (initialize, ping, tools/list, etc.)
3. For `tools/call`: payload extracted and flattened
4. Detection runs via `BinaryMCPDetector.predict()` in threadpool
5. If blocked: JSON-RPC error with class/confidence
6. If allowed: forwarded via `mcp_bridge/src/services/forwarder.py`

### Detector Facade
`mcp_bridge/src/core/detector.py`:
- `BinaryMCPDetector`: Singleton facade for all detectors
- `fit()`: Train detectors on labeled samples
- `predict()`: Ensemble prediction
- `save_models()` / `load_models()`: Model persistence
- `provide_feedback()`: Supervised feedback for weight adjustment

### Data Models
`mcp_bridge/src/models.py`:
- `JsonRpcRequest`: JSON-RPC 2.0 request validation
- `JsonRpcResponse`: Response formatting
- `SecurityClass`: Enum for BENIGN/ATTACK

`mcp_bridge/src/core/detectors/base.py`:
- `DetectionResult`: Unified result format
- `BaseDetector`: Abstract base class

### Audit Logging
`mcp_bridge/src/core/utils.py`:
- `log_thesis_data()`: JSONL logging for analysis
- Rotating log files (10MB per file, 5 backups)

## Environment Variables

### Bridge Configuration
```env
LOG_LEVEL=INFO
DEBUG=false
MODEL_NAME=distilbert-base-uncased
DETECTOR_SIGMA=3.0

# MCP Server Discovery
MCP_SERVERS=http://tool-filesystem:8080,http://tool-sqlite:8080,http://tool-time:8080,http://tool-fetch:8080,http://tool-memory:8080

# Model Paths
RESEARCH_DATA_PATH=/app/research_data
TRAINING_DATA_FILE=training_dataset.json
SEMANTIC_MODEL_PATH=/app/trained_models/semantic_model.pt
STATISTICAL_MODEL_PATH=/app/trained_models/statistical_model.pt
MAML_MODEL_PATH=/app/trained_models/maml_model.pt
AUDIT_LOG_PATH=/app/research_data/runtime_audit.jsonl
```

### MAML Configuration (Optional)
```env
MAML_ENABLED=false
MAML_META_LR=0.001
MAML_INNER_LR=0.01
MAML_ADAPTATION_STEPS=5
MAML_FIRST_ORDER=true
MAML_SHOTS=5
MAML_HIDDEN_DIM=256
MAML_CONFIDENCE_THRESHOLD=0.6
MAML_NUM_META_EPOCHS=100
```

### LLM Service Configuration
```env
LLM_MODEL_PATH=/app/models/llama-2-7b-chat.Q4_K_M.gguf
LLM_N_GPU_LAYERS=-1
LLM_N_CTX=4096
LLM_CHAT_FORMAT=llama-2

# Cloud LLM
CLOUD_LLM_PROVIDER=openai  # or 'gemini'
CLOUD_OPENAI_API_KEY=...
CLOUD_GOOGLE_API_KEY=...
```

## Development Patterns

### Async/FastAPI
- Use `async def` for all handlers
- CPU-bound operations (ML inference) run in threadpool: `await run_in_threadpool(detector.predict, ...)`
- Tool communication uses `httpx.AsyncClient` with connection pooling

### Adding New MCP Servers
1. Add server to `docker compose.yml` on `mcp-secure` network
2. Add URL to `MCP_SERVERS` env var (comma-separated)
3. Restart bridge - auto-discovers tools via `tools/list`

### Training Data Format
Tool-keyed dict with "benign" and "attack" keys:
```json
{
  "read_file": {
    "benign": ["{\"path\": \"docs/readme.txt\"}", ...],
    "attack": ["{\"path\": \"../../../etc/passwd\"}", ...]
  }
}
```

### Singleton Pattern
`BinaryMCPDetector` uses singleton pattern to avoid reloading models. Use `BinaryMCPDetector.reset_instance()` to recover from initialization failures or for testing.

## Important Constraints

1. **MCP Protocol Compliance**: Bridge must not break MCP compatibility. Standard JSON-RPC 2.0 requests pass through unmodified (except when blocked).

2. **Network Isolation**: Tools on `mcp-secure` network must be in an isolated network.

3. **Binary Classification**: System uses 2-class model (BENIGN vs ATTACK). All threat types merged into ATTACK.

4. **Zero-Trust for New Tools**: Tools without training data default-deny all requests.

5. **Async Patterns**: The MCP bridge acts as a bottleneck if not properly using async patterns. Never run blocking operations in FastAPI handlers without threadpool/async wrapper.

## Troubleshooting

### Common Issues

**Bridge fails to start / "No training data found"**
```bash
ls research/data/training_dataset.json
# If missing, runs in ZERO-SHOT mode (high false positives)
```

**Tools not discovered**
```bash
docker compose ps
docker compose logs mcp-bridge | grep -i "discovery\|registered"
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

**All requests blocked (high false positives)**
```bash
# Increase sigma for lenient detection
DETECTOR_SIGMA=4.0 docker compose up -d mcp-bridge
```

**Model retraining**
```bash
rm research/trained_models/*.pt
docker compose restart mcp-bridge
```

### Debugging Commands
```bash
# Real-time logs
docker compose logs -f mcp-bridge

# Test MCP initialize
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"clientInfo":{"name":"debug","version":"1.0"}},"id":1}'

# Test tool call (should be blocked if attack)
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../etc/passwd"}},"id":1}'

# View audit logs
tail -f research/data/runtime_audit.jsonl
```

## Research Context


Scientific evaluation notebooks in `research/notebooks/`:
- `model_comparisons.ipynb`: ROC curves, precision-recall, per-detector analysis
- `semantic_evaluation.ipynb`: Semantic detector deep-dive
- `statistical_evaluation.ipynb`: Statistical detector analysis
- `maml_evaluation.ipynb`: MAML few-shot learning evaluation
- `rule_based_evaluation.ipynb`: Rule-based detector analysis
- `dataset_validation.ipynb`: Dataset integrity checks

## FAQ

**Q: How do I add a new MCP server?**
A: Add URL to `MCP_SERVERS` env var, restart bridge. It auto-discovers tools.

**Q: How do I train on new tools?**
A: Add samples to `research/data/training_dataset.json`, delete cached models, restart bridge.

**Q: Why binary classification?**
A: Simpler, faster, more accurate. All threats merged into "attack" eliminates ambiguity.

**Q: How do I lower false positives?**
A: Increase `DETECTOR_SIGMA` (default: 3.0). Higher = more lenient.

**Q: Can I use this with Claude Desktop?**
A: Yes. Point MCP client to `http://localhost:8000`. Bridge is MCP 2024-11-05 compliant.
