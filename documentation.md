# MCP Security Proxy - Complete Technical Documentation

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Project Structure](#project-structure)
3. [Architecture Overview](#architecture-overview)
4. [Core Components](#core-components)
   - [MCP Bridge (Security Proxy)](#mcp-bridge-security-proxy)
   - [Detection System](#detection-system)
   - [MCP Tool Servers](#mcp-tool-servers)
   - [LLM Services](#llm-services)
   - [Client Utilities](#client-utilities)
   - [Research Components](#research-components)
5. [Design Decisions & Rationale](#design-decisions--rationale)
6. [Data Flow & Request Processing](#data-flow--request-processing)
7. [Configuration Reference](#configuration-reference)
8. [Deployment & Operations](#deployment--operations)
9. [Testing & Evaluation](#testing--evaluation)
10. [API Reference](#api-reference)

---

## Executive Summary

This project implements a **Transparent Security Proxy** for the Model Context Protocol (MCP), designed to protect Language Model applications from malicious tool calls. The system sits between LLM clients and MCP tool servers, inspecting every request using an ensemble of machine learning-based anomaly detectors.

### Key Characteristics

| Aspect | Choice | Rationale |
|--------|--------|-----------|
| Classification | Binary (BENIGN vs ATTACK) | Simpler decision boundary, faster inference, higher accuracy |
| Architecture | Transparent Proxy | Drop-in security layer, no tool modification required |
| Detection | Ensemble ML | Multiple detectors provide robustness against evasion |
| Fail-Safe | Default to ATTACK | Security-first: ambiguous cases are blocked |
| Protocol | MCP 2024-11-05 compliant | Industry standard for LLM tool use |

### Thesis Context

This is a master's thesis research project investigating ML-based security for LLM tool interactions. The primary research questions address:
- Effectiveness of prototypical learning for security classification
- Few-shot adaptation to new tools via meta-learning (MAML)
- Ensemble methods for robust anomaly detection
- Latency-accuracy tradeoffs in real-time security screening

---

## Project Structure

```
MCP Security Proxy/
├── CLAUDE.md                           # Claude Code instructions
├── documentation.md                    # This file
├── readme.md                           # Project overview
├── requirements.txt                    # Root Python dependencies
├── docker-compose.yml                  # Service orchestration (12 services)
│
├── mcp_bridge/                         # CORE: Security proxy service
│   ├── Dockerfile
│   ├── requirements.txt
│   └── src/
│       ├── __init__.py
│       ├── main.py                     # FastAPI application, JSON-RPC handlers
│       ├── config.py                   # Settings with pydantic-settings
│       ├── models.py                   # Pydantic models, SecurityClass enum
│       ├── core/
│       │   ├── __init__.py
│       │   ├── detector.py             # BinaryMCPDetector ensemble facade
│       │   ├── utils.py                # Audit logging (JSONL)
│       │   └── detectors/
│       │       ├── __init__.py         # Detector exports
│       │       ├── base.py             # BaseDetector, DetectionResult, SecurityClass
│       │       ├── rule_based.py       # Regex pattern matching detector
│       │       ├── statistical.py      # Mahalanobis distance detector
│       │       ├── semantic.py         # DistilBERT prototypical detector
│       │       └── maml.py             # MAML meta-learning detector
│       └── services/
│           ├── __init__.py
│           └── forwarder.py            # HTTP client for tool routing
│
├── mcp_tools/                          # MCP-compliant tool servers
│   ├── filesystem/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   ├── server.py                   # File operations MCP server
│   │   └── info.md
│   ├── sqlite/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   ├── server.py                   # Database operations MCP server
│   │   ├── init_db.py                  # Database initialization
│   │   └── info.md
│   ├── time/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── server.py                   # Timezone operations MCP server
│   ├── fetch/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── server.py                   # Web content fetching MCP server
│   └── memory/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── server.py                   # Knowledge graph MCP server
│
├── llm_service/                        # Local LLM inference
│   ├── Dockerfile
│   ├── requirements.txt
│   └── server.py                       # llama-cpp-python server
│
├── llm_cloud_service/                  # Cloud LLM adapter
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── info.md
│   └── src/
│       ├── __init__.py
│       ├── config.py                   # OpenAI/Gemini settings
│       └── main.py                     # FastAPI cloud adapter
│
├── client/                             # Testing utilities
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── agent.py                        # Interactive chat agent
│   ├── test_tools.py                   # Direct tool testing
│   ├── traffic_generator.py           # Load testing & attack simulation
│   ├── latency_test.py                 # Performance benchmarking
│   └── mcp_agent.md                    # Agent documentation
│
├── research/                           # Thesis research artifacts
│   ├── requirements.txt
│   ├── data/
│   │   ├── training_dataset.json       # Training data (benign + attack samples)
│   │   ├── test_dataset.json           # Test data
│   │   ├── validation_dataset.json     # Validation data
│   │   ├── owasp_training_dataset.json # OWASP-based training data
│   │   ├── owasp_test_dataset.json     # OWASP-based test data
│   │   ├── owasp_validation_dataset.json
│   │   └── runtime_audit.jsonl         # Runtime audit logs
│   ├── trained_models/
│   │   ├── semantic_model.pt           # Trained SemanticDetector
│   │   ├── statistical_model.pt        # Trained StatisticalDetector
│   │   └── maml_model.pt               # Trained MAMLDetector
│   ├── notebooks/
│   │   ├── dataset_validation.ipynb    # Dataset integrity checks
│   │   ├── model_comparisons.ipynb     # ROC, precision-recall analysis
│   │   ├── semantic_evaluation.ipynb   # Semantic detector deep-dive
│   │   ├── statistical_evaluation.ipynb # Statistical detector analysis
│   │   ├── maml_evaluation.ipynb       # MAML few-shot evaluation
│   │   └── rule_based_evaluation.ipynb # Rule-based analysis
│   ├── evaluation_results/
│   │   ├── semantic_summary.json
│   │   ├── statistical_summary.json
│   │   ├── maml_summary.json
│   │   └── rule_based_summary.json
│   ├── figures/                        # Generated plots
│   │   ├── semantic/
│   │   ├── statistical/
│   │   ├── maml/
│   │   └── rule_based/
│   ├── logs/                           # Training logs
│   └── tools/
│       ├── train_models.py             # Standalone training script
│       ├── verify_datasets.py          # Dataset integrity checker
│       ├── analyze_patterns.py         # Attack signature analysis
│       ├── fix_overlap.py              # Remove train/test overlap
│       ├── add_payloads.py             # Add attack payloads
│       ├── create_owasp_datasets.py    # Generate OWASP datasets
│       ├── detect_duplicates.py        # Duplicate sample detection
│       ├── check_semantic_leakage.py   # Semantic similarity leakage check
│       └── stdio_client_adapter.py     # STDIO MCP client adapter
│
└── sandbox_files/                      # Test sandbox for filesystem tool
    ├── README.md
    ├── config/
    │   └── app_settings.yml
    ├── data/
    │   ├── hello_world.txt
    │   └── transactions.json
    ├── documents/
    ├── images/
    ├── logs/
    ├── memory/
    │   └── memory.json
    ├── scripts/
    │   └── analyze.py
    ├── secret/
    │   └── env.txt
    ├── system/
    └── temp/
```

---

## Architecture Overview

### Network Topology

The system uses Docker Compose to orchestrate services across two isolated networks:
```
[ mcp-client ] --(mcp-public)--> [ mcp-bridge (security proxy) ] --(mcp-secure)--> [ mcp-tool-servers ]
```

### Design Rationale: Network Isolation

**Why two networks?**

1. **Defense in Depth**: Even if an attacker bypasses the security proxy, tools on `mcp-secure` cannot exfiltrate data to the internet (`internal: true` flag prevents outbound connections).

2. **Blast Radius Limitation**: A compromised tool cannot pivot to attack external systems.

3. **Compliance**: Many security frameworks require network segmentation for sensitive operations.

---

## Core Components

### MCP Bridge (Security Proxy)

**Location**: `mcp_bridge/`

**Purpose**: Transparent security proxy that intercepts all MCP JSON-RPC requests, classifies them using an ML ensemble, and either forwards safe requests or blocks attacks.

#### Main Application (`mcp_bridge/src/main.py`)

The FastAPI application serves as the central entry point:

```python
# Key endpoints
POST /jsonrpc          # Main JSON-RPC 2.0 endpoint
POST /                 # Alias for /jsonrpc (MCP compatibility)
GET  /health           # Health check endpoint
```

**MCP Protocol Support**:
- `initialize` - Client handshake with capability negotiation
- `ping` - Health check
- `tools/list` - Enumerate available tools (with pagination)
- `tools/call` - Execute tool (security-screened)
- `resources/list` - Resource enumeration (placeholder)
- `prompts/list` - Prompt template enumeration (placeholder)

**Request Processing Flow**:

```python
async def handle_jsonrpc(request: JsonRpcRequest):
    # 1. Protocol method handling (initialize, ping, tools/list)
    if request.method in MCP_PROTOCOL_METHODS:
        return handle_protocol_method(request)

    # 2. Tool call security screening
    if request.method == "tools/call":
        tool_name = request.params["name"]
        arguments = request.params["arguments"]
        payload = flatten_payload(tool_name, arguments)

        # 3. Run detection in threadpool (CPU-bound)
        result = await run_in_threadpool(
            detector.predict, payload, tool_name
        )

        # 4. Block or forward
        if not result.allowed:
            log_thesis_data(request_id, tool_name, payload, result)
            return JsonRpcError(code=-32000, message="Security violation")

        # 5. Forward to appropriate tool server
        return await forwarder.forward(tool_name, request)
```

**Why FastAPI?**
- Async-native for high throughput
- Automatic OpenAPI documentation
- Pydantic integration for request validation
- Easy threadpool integration for CPU-bound ML inference

#### Configuration (`mcp_bridge/src/config.py`)

Uses `pydantic-settings` for type-safe configuration:

```python
class Settings(BaseSettings):
    # Logging
    log_level: str = "INFO"
    debug: bool = False

    # Model settings
    model_name: str = "distilbert-base-uncased"

    # Detection thresholds
    detector_sigma: float = 3.0  # 3-sigma rule

    # MCP servers (auto-discovered)
    mcp_servers: List[str] = [...]

    # Model paths
    semantic_model_path: str = "..."
    statistical_model_path: str = "..."
    maml_model_path: str = "..."

    class Config:
        env_prefix = ""  # No prefix for env vars
```

**Why pydantic-settings?**
- Type validation at startup
- Environment variable binding
- Default values with override capability
- Documentation via type hints

#### Request Forwarder (`mcp_bridge/src/services/forwarder.py`)

Handles HTTP routing to backend MCP servers:

```python
class RequestForwarder:
    def __init__(self, mcp_servers: List[str]):
        self.client = httpx.AsyncClient(timeout=30.0)
        self.tool_routes: Dict[str, str] = {}

    async def discover_tools(self):
        """Query each server for tools/list and build routing table."""
        for server_url in self.mcp_servers:
            response = await self.client.post(
                server_url,
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            )
            tools = response.json()["result"]["tools"]
            for tool in tools:
                self.tool_routes[tool["name"]] = server_url

    async def forward(self, tool_name: str, request: JsonRpcRequest):
        """Forward request to appropriate backend server."""
        server_url = self.tool_routes.get(tool_name)
        if not server_url:
            raise ValueError(f"Unknown tool: {tool_name}")
        return await self.client.post(server_url, json=request.dict())
```

**Why dynamic discovery?**
- No hardcoded tool mappings
- Servers can add/remove tools dynamically
- Supports any MCP-compliant server

---

### Detection System

**Location**: `mcp_bridge/src/core/`

The detection system uses an **ensemble architecture** with four specialized detectors coordinated by a facade class.

#### BinaryMCPDetector Facade (`mcp_bridge/src/core/detector.py`)

**Design Pattern**: Singleton + Facade

```python
class BinaryMCPDetector:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return

        # Initialize detectors
        self.rule_based = RuleBasedDetector()
        self.statistical = StatisticalFeatureDetector()
        self.semantic = SemanticDetector()
        self.maml = MAMLDetector() if MAML_ENABLED else None

        # Ensemble weights (empirically tuned)
        self.weights = {
            "rule_based": 0.40,
            "semantic": 0.35,
            "statistical": 0.15,
            "maml": 0.10
        }

        self._initialized = True
```

**Why Singleton?**
- Models are expensive to load (DistilBERT ~260MB)
- Avoid redundant memory usage
- Consistent state across requests

**Ensemble Prediction Logic**:

```python
def predict(self, payload: str, tool_name: str) -> DetectionResult:
    votes = {}
    confidences = {}

    # 1. Rule-based check (fast path)
    rule_result = self.rule_based.predict(payload, tool_name)
    if rule_result and rule_result.security_class == SecurityClass.ATTACK:
        # High-confidence attack from rules - return immediately
        return rule_result

    # 2. Collect votes from ML detectors
    for name, detector in self.ml_detectors.items():
        result = detector.predict(payload, tool_name)
        if result:
            votes[name] = result.security_class
            confidences[name] = result.confidence

    # 3. Weighted voting
    benign_score = sum(
        self.weights[name] * confidences[name]
        for name, vote in votes.items()
        if vote == SecurityClass.BENIGN
    )
    attack_score = sum(
        self.weights[name] * confidences[name]
        for name, vote in votes.items()
        if vote == SecurityClass.ATTACK
    )

    # 4. Fail-safe margin check
    margin = benign_score - attack_score
    if margin < 0.10:  # Less than 10% margin
        return DetectionResult.attack(
            confidence=attack_score,
            reason="Fail-safe: margin below threshold"
        )

    # 5. Return majority vote
    if benign_score > attack_score:
        return DetectionResult.benign(confidence=benign_score)
    else:
        return DetectionResult.attack(confidence=attack_score)
```

**Why Ensemble?**
- No single detector is perfect
- Rule-based catches known attacks quickly
- ML detectors catch novel attacks
- Weighted voting provides robustness

#### Base Classes (`mcp_bridge/src/core/detectors/base.py`)

```python
class SecurityClass(Enum):
    BENIGN = "benign"
    ATTACK = "attack"

@dataclass
class DetectionResult:
    security_class: SecurityClass
    confidence: float
    reason: str
    metadata: Dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.security_class == SecurityClass.BENIGN

    @classmethod
    def benign(cls, confidence: float, reason: str = "") -> "DetectionResult":
        return cls(SecurityClass.BENIGN, confidence, reason, {})

    @classmethod
    def attack(cls, confidence: float, reason: str = "") -> "DetectionResult":
        return cls(SecurityClass.ATTACK, confidence, reason, {})

class BaseDetector(ABC):
    @abstractmethod
    def fit(self, tool_name: str, benign: List[str], attack: List[str]):
        """Train detector on labeled samples."""
        pass

    @abstractmethod
    def predict(self, payload: str, tool_name: str) -> Optional[DetectionResult]:
        """Classify payload. Returns None to defer to other detectors."""
        pass

    @abstractmethod
    def save_state(self) -> Dict[str, Any]:
        """Serialize detector state for persistence."""
        pass

    @abstractmethod
    def load_state(self, state: Dict[str, Any]):
        """Restore detector from serialized state."""
        pass
```

#### RuleBasedDetector (`mcp_bridge/src/core/detectors/rule_based.py`)

**Purpose**: Fast pattern matching for known attack signatures.

**Attack Patterns Detected**:

| Category | Example Patterns |
|----------|-----------------|
| Path Traversal | `../`, `..\\`, `%2e%2e%2f`, encoded variants |
| SQL Injection | `' OR '1'='1`, `UNION SELECT`, `; DROP TABLE` |
| Command Injection | `$(cmd)`, `` `cmd` ``, `; cmd`, `| cmd` |
| SSRF | `localhost`, `127.0.0.1`, `169.254.169.254` |
| XSS | `<script>`, `javascript:`, event handlers |

```python
class RuleBasedDetector(BaseDetector):
    PATTERNS = {
        "path_traversal": [
            r'\.\.[/\\]',
            r'%2e%2e[%2f/\\]',
            r'\.\.%c0%af',
        ],
        "sql_injection": [
            r"'\s*(OR|AND)\s*['\d]",
            r"UNION\s+(ALL\s+)?SELECT",
            r";\s*DROP\s+TABLE",
            r"'\s*--",
        ],
        "command_injection": [
            r'\$\([^)]+\)',
            r'`[^`]+`',
            r';\s*\w+',
            r'\|\s*\w+',
        ],
        # ... more patterns
    }

    def predict(self, payload: str, tool_name: str) -> Optional[DetectionResult]:
        for category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    return DetectionResult.attack(
                        confidence=0.95,
                        reason=f"Rule match: {category}"
                    )
        return None  # Defer to other detectors
```

**Why Rule-Based First?**
- Extremely fast (~microseconds)
- High precision for known attacks
- Provides explainable decisions
- Catches attacks that ML might miss

#### StatisticalFeatureDetector (`mcp_bridge/src/core/detectors/statistical.py`)

**Purpose**: Anomaly detection using statistical features and Mahalanobis distance.

**Feature Extraction**:

```python
def extract_features(self, payload: str) -> np.ndarray:
    return np.array([
        len(payload),                           # Length
        self._entropy(payload),                  # Shannon entropy
        self._special_char_ratio(payload),       # Special character density
        self._digit_ratio(payload),              # Digit density
        self._uppercase_ratio(payload),          # Uppercase density
        self._suspicious_pattern_count(payload), # Suspicious keyword count
        self._max_token_length(payload),         # Longest token
        self._nested_depth(payload),             # Nesting depth
    ])
```

**Mahalanobis Distance Classification**:

```python
def predict(self, payload: str, tool_name: str) -> Optional[DetectionResult]:
    features = self.extract_features(payload)

    # Compute distance to each class centroid
    benign_dist = self._mahalanobis_distance(
        features,
        self.centroids[tool_name]["benign"],
        self.covariances[tool_name]
    )
    attack_dist = self._mahalanobis_distance(
        features,
        self.centroids[tool_name]["attack"],
        self.covariances[tool_name]
    )

    # Classify based on closer centroid with margin
    margin = attack_dist - benign_dist
    if margin > self.threshold:
        return DetectionResult.benign(confidence=self._dist_to_conf(margin))
    else:
        return DetectionResult.attack(confidence=self._dist_to_conf(-margin))
```

**Why Mahalanobis Distance?**
- Accounts for feature correlations (unlike Euclidean)
- Scale-invariant
- Works well with multivariate Gaussian assumption
- Provides interpretable distance metric

#### SemanticDetector (`mcp_bridge/src/core/detectors/semantic.py`)

**Purpose**: Deep semantic understanding using transformer embeddings and prototypical learning.

**Architecture**:

```
Input Payload → Tokenizer → DistilBERT → [CLS] Embedding → Prototype Comparison → Class
                                              ↓
                                    768-dim normalized vector
```

**Prototypical Learning**:

The detector maintains **class prototypes** for each tool - centroid embeddings computed from training samples:

```python
def fit(self, tool_name: str, benign: List[str], attack: List[str]):
    # Compute embeddings for all samples
    benign_embeddings = [self._get_embedding(s) for s in benign]
    attack_embeddings = [self._get_embedding(s) for s in attack]

    # Compute class prototypes (centroids)
    self.prototypes[tool_name] = {
        "benign": np.mean(benign_embeddings, axis=0),
        "attack": np.mean(attack_embeddings, axis=0)
    }

    # Compute data-driven thresholds from training distribution
    self._compute_thresholds(tool_name, benign_embeddings, attack_embeddings)
```

**Prediction with Cosine Similarity**:

```python
def predict(self, payload: str, tool_name: str) -> Optional[DetectionResult]:
    embedding = self._get_embedding(payload)

    # Cosine similarity to prototypes
    benign_sim = cosine_similarity(embedding, self.prototypes[tool_name]["benign"])
    attack_sim = cosine_similarity(embedding, self.prototypes[tool_name]["attack"])

    # Margin-based classification with data-driven threshold
    margin = benign_sim - attack_sim
    threshold = self.thresholds[tool_name]

    if margin > threshold:
        return DetectionResult.benign(confidence=self._calibrate(margin))
    else:
        return DetectionResult.attack(confidence=self._calibrate(-margin))
```

**Why Prototypical Learning?**
- Works well with limited training data
- No complex classifier training required
- Naturally handles new tools (just compute prototypes)
- Interpretable: "How similar to known benign/attack?"

**Why DistilBERT?**
- 40% smaller than BERT, 60% faster
- Retains 97% of BERT's language understanding
- Good for production deployment
- Pre-trained on large corpus captures semantic meaning

#### MAMLDetector (`mcp_bridge/src/core/detectors/maml.py`)

**Purpose**: Few-shot adaptation to new tools using Model-Agnostic Meta-Learning.

**MAML Overview**:

MAML learns an initialization that can quickly adapt to new tasks with few examples. The key insight is that the model learns "how to learn" rather than learning a fixed classifier.

```
Meta-Training Phase:
┌───────────────────────────────────────────────────────────────────────┐
│  For each meta-batch:                                           │
│    1. Sample tasks (tools) from training distribution           │
│    2. For each task:                                            │
│       a. Sample K-shot support set                              │
│       b. Adapt model with few gradient steps (inner loop)       │
│       c. Evaluate on query set                                  │
│    3. Update meta-parameters based on query performance         │
└───────────────────────────────────────────────────────────────────────┘

Deployment Phase:
┌───────────────────────────────────────────────────────────────────────┐
│  For new tool:                                                  │
│    1. Collect K examples per class                              │
│    2. Adapt from meta-learned initialization (5 gradient steps) │
│    3. Deploy adapted model for that tool                        │
└───────────────────────────────────────────────────────────────────────┘
```

**Architecture**:

```python
class MAMLClassifier(nn.Module):
    def __init__(self, config: MAMLConfig):
        self.classifier = nn.Sequential(
            nn.Linear(768, 256),      # DistilBERT dim → hidden
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 128),      # hidden → hidden/2
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 2)         # hidden/2 → 2 classes
        )
```

**Meta-Training Loop**:

```python
def meta_train(self, all_tool_data: Dict[str, Dict[str, List[str]]]):
    meta_optimizer = Adam(self.meta_model.parameters(), lr=0.001)

    for epoch in range(num_epochs):
        # Sample batch of tasks (tools)
        tasks = self._sample_task_batch(all_tool_data)

        task_losses = []
        for support_x, support_y, query_x, query_y in tasks:
            # Inner loop: adapt to this task
            adapted_params = self._inner_loop(
                self.meta_model.parameters(),
                support_x, support_y,
                steps=5, lr=0.01
            )

            # Evaluate on query set
            query_loss = F.cross_entropy(
                self._forward(adapted_params, query_x),
                query_y
            )
            task_losses.append(query_loss)

        # Outer loop: update meta-parameters
        meta_loss = torch.stack(task_losses).mean()
        meta_optimizer.zero_grad()
        meta_loss.backward()
        meta_optimizer.step()
```

**Why MAML?**
- Can adapt to new tools with just 5-10 examples per class
- Learns transferable features across tools
- Explicit optimization objective for fast adaptation
- Theoretically grounded (Finn et al., ICML 2017)

**Limitations**:
- More compute-intensive than other detectors
- Requires diverse meta-training tasks
- First-order approximation trades accuracy for speed

---

### MCP Tool Servers

**Location**: `mcp_tools/`

Each tool server implements the MCP specification and provides domain-specific functionality.

#### Common MCP Server Pattern

All tool servers follow the same JSON-RPC 2.0 pattern:

```python
@app.post("/")
async def handle_rpc(request: Request):
    body = await request.json()
    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "result": {"tools": TOOLS_METADATA},
            "id": req_id
        }

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})

        try:
            result = await execute_tool(tool_name, args)
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result)}],
                    "isError": False
                },
                "id": req_id
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": str(e)}],
                    "isError": True
                },
                "id": req_id
            }
```

#### Filesystem Tool (`mcp_tools/filesystem/server.py`)

**Tools Provided**:

| Tool | Description | Security Considerations |
|------|-------------|------------------------|
| `read_file` | Read file contents | Path traversal, sensitive file access |
| `write_file` | Write/create files | Arbitrary file write, code injection |
| `list_directory` | List directory contents | Information disclosure |
| `search_files` | Search by pattern | Resource exhaustion, path traversal |
| `create_directory` | Create directories | Directory traversal |

**Security Features** (when `SAFE_MODE=true`):
- Path validation to prevent traversal
- Allowed paths whitelist
- Blocked file extensions (`.env`, `.key`, etc.)

#### SQLite Tool (`mcp_tools/sqlite/server.py`)

**Tools Provided**:

| Tool | Description | Security Considerations |
|------|-------------|------------------------|
| `read_query` | Execute SELECT queries | SQL injection, data exfiltration |
| `write_query` | Execute INSERT/UPDATE/DELETE | Data modification, injection |
| `list_tables` | List database tables | Schema enumeration |
| `describe_table` | Get table schema | Schema disclosure |

**Why SQLite?**
- Self-contained (no external database server)
- Perfect for testing SQL injection detection
- Realistic attack surface

#### Time Tool (`mcp_tools/time/server.py`)

**Tools Provided**:

| Tool | Description | Security Considerations |
|------|-------------|------------------------|
| `get_current_time` | Get current time in timezone | Command injection in timezone |
| `convert_time` | Convert between timezones | Injection in timezone parameters |

**Why Include Time Tool?**
- Demonstrates that even "simple" tools can have injection vectors
- Timezone parameter could be exploited for command injection

#### Fetch Tool (`mcp_tools/fetch/server.py`)

**Tools Provided**:

| Tool | Description | Security Considerations |
|------|-------------|------------------------|
| `fetch_url` | Fetch URL content | SSRF, internal network access |
| `fetch_html` | Fetch and parse HTML | SSRF, content injection |
| `check_url` | Check URL accessibility | SSRF, port scanning |

**SSRF Protection** (when `SAFE_MODE=true`):

```python
BLOCKED_PATTERNS = [
    r'^https?://localhost',
    r'^https?://127\.',
    r'^https?://10\.',
    r'^https?://172\.(1[6-9]|2[0-9]|3[01])\.',
    r'^https?://192\.168\.',
    r'^https?://169\.254\.',  # AWS metadata
    r'^https?://\[::1\]',     # IPv6 localhost
    r'^file://',
    r'^gopher://',
]
```

#### Memory Tool (`mcp_tools/memory/server.py`)

**Tools Provided**:

| Tool | Description | Security Considerations |
|------|-------------|------------------------|
| `create_entity` | Create knowledge graph entity | Injection in entity content |
| `get_entity` | Retrieve entity | Path traversal in entity name |
| `search_entities` | Search entities | Injection in search query |
| `create_relation` | Create entity relation | Privilege escalation |
| `get_relations` | Get entity relations | Information disclosure |
| `delete_entity` | Delete entity | Unauthorized deletion |
| `list_entities` | List all entities | Enumeration |

**Why Knowledge Graph Tool?**
- Represents complex state management
- Tests detection of semantic attacks (not just syntax)
- Demonstrates relation manipulation attacks

---

### LLM Services

#### Local LLM Service (`llm_service/server.py`)

Uses `llama-cpp-python` to run quantized GGUF models locally:

```python
from llama_cpp import Llama

llm = Llama(
    model_path=os.getenv("LLM_MODEL_PATH"),
    n_gpu_layers=-1,  # Use all GPU layers
    n_ctx=4096,
    chat_format="llama-2"
)

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    response = llm.create_chat_completion(
        messages=request.messages,
        temperature=request.temperature,
        max_tokens=request.max_tokens
    )
    return response
```

**Supported Models**:
- Llama-2-7B-Chat (Q4_K_M quantization)
- Llama-3-8B-Instruct
- Mistral-7B-Instruct

**Why Local LLM?**
- Privacy: No data leaves local environment
- Cost: No API fees for high-volume testing
- Control: Reproducible experiments

#### Cloud LLM Service (`llm_cloud_service/src/main.py`)

Provides a unified adapter for cloud LLM providers:

```python
class Settings(BaseSettings):
    llm_provider: Literal["openai", "gemini"] = "openai"
    openai_api_key: str = ""
    google_api_key: str = ""
    model_name: str = "gpt-3.5-turbo"

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    if settings.llm_provider == "openai":
        return await call_openai(request)
    elif settings.llm_provider == "gemini":
        return await call_gemini(request)
```

**Why Cloud Adapter?**
- Production scenarios use cloud LLMs
- Test with different model capabilities
- Compare local vs cloud performance

---

### Client Utilities

**Location**: `client/`

#### Interactive Agent (`client/agent.py`)

Chat interface that demonstrates the full LLM → Security Proxy → Tool flow:

```python
async def chat_loop():
    while True:
        user_input = input("You: ")

        # Send to LLM with tool schemas
        response = await llm_client.chat(
            messages=[{"role": "user", "content": user_input}],
            tools=available_tools
        )

        # Handle tool calls
        if response.tool_calls:
            for tool_call in response.tool_calls:
                # Call tool through bridge (security screening)
                result = await bridge_client.call_tool(
                    tool_call.name,
                    tool_call.arguments
                )
                print(f"Tool result: {result}")
```

#### Traffic Generator (`client/traffic_generator.py`)

Generates mixed traffic for testing detection accuracy:

```python
# Traffic categories
BENIGN_PAYLOADS = [...]      # Normal usage patterns
SENSITIVE_PAYLOADS = [...]   # Policy-restricted but not attacks
MALICIOUS_PAYLOADS = [...]   # Known attack patterns
ZERO_DAY_PAYLOADS = [...]    # Novel attack patterns

async def generate_traffic(
    total_samples: int = 100,
    malicious_ratio: float = 0.25,
    sensitive_ratio: float = 0.2,
    anomalous_ratio: float = 0.1,
    concurrency: int = 5
):
    # Generate balanced traffic
    # Measure detection accuracy and latency
```

**Attack Categories Tested**:
- Path traversal (various encodings)
- SQL injection (basic, UNION, blind, stacked)
- Command injection (various shells)
- SSRF (IP formats, protocols)
- XSS/Injection in entity content

---

### Research Components

**Location**: `research/`

#### Datasets

| Dataset | Purpose | Format |
|---------|---------|--------|
| `training_dataset.json` | Model training | `{tool: {benign: [...], attack: [...]}}` |
| `test_dataset.json` | Final evaluation | Same format |
| `validation_dataset.json` | Hyperparameter tuning | Same format |
| `owasp_*.json` | OWASP-based attack patterns | Same format |
| `runtime_audit.jsonl` | Runtime logs | JSONL with predictions |

#### Training Script (`research/tools/train_models.py`)

```bash
# Train semantic and statistical detectors
python research/tools/train_models.py

# Train with MAML (takes longer)
python research/tools/train_models.py --maml --maml-epochs 100
```

#### Evaluation Notebooks

| Notebook | Purpose |
|----------|---------|
| `model_comparisons.ipynb` | ROC curves, precision-recall, per-detector comparison |
| `semantic_evaluation.ipynb` | Embedding visualization, prototype analysis |
| `statistical_evaluation.ipynb` | Feature importance, decision boundaries |
| `maml_evaluation.ipynb` | Few-shot learning curves |
| `rule_based_evaluation.ipynb` | Pattern coverage analysis |
| `dataset_validation.ipynb` | Data quality, leakage detection |

---

## Design Decisions & Rationale

### Why Binary Classification?

**Alternative**: Multi-class (Benign, SQLi, XSS, Path Traversal, etc.)

**Chosen**: Binary (Benign vs Attack)

**Rationale**:
1. **Simpler decision boundary**: Two classes are easier to separate than many
2. **Faster inference**: Single binary decision vs multi-class softmax
3. **Higher accuracy**: Attack types share features (special characters, unusual structure)
4. **Actionable**: The only decision needed is "allow or block"
5. **Avoids ambiguity**: "Is this SQLi or command injection?" doesn't matter for blocking

### Why Ensemble Architecture?

**Alternative**: Single strong model (e.g., fine-tuned BERT classifier)

**Chosen**: Ensemble of specialized detectors

**Rationale**:
1. **Defense in depth**: If one detector is evaded, others may catch the attack
2. **Complementary strengths**:
   - Rule-based: Fast, catches known patterns
   - Statistical: Catches anomalous structure
   - Semantic: Catches semantic attacks
   - MAML: Adapts to new tools quickly
3. **Graceful degradation**: If one detector fails, others continue
4. **Explainability**: Can attribute decisions to specific detectors

### Why Fail-Safe to ATTACK?

**Alternative**: Fail-safe to BENIGN (permissive)

**Chosen**: Fail-safe to ATTACK (restrictive)

**Rationale**:
1. **Security first**: False positives are less costly than false negatives
2. **A blocked legitimate request can be manually reviewed**
3. **A passed attack can cause real damage**
4. **Aligns with zero-trust principles**

### Why Transparent Proxy?

**Alternative**: Tool modification (add security hooks to each tool)

**Chosen**: Transparent proxy (intercept and forward)

**Rationale**:
1. **No tool changes required**: Works with any MCP-compliant server
2. **Single point of enforcement**: All security logic in one place
3. **Easy deployment**: Add proxy to existing setup
4. **Protocol compliant**: Standard MCP flows work unchanged

### Why DistilBERT?

**Alternative**: BERT, RoBERTa, GPT embeddings

**Chosen**: DistilBERT

**Rationale**:
1. **Size**: 66M parameters vs BERT's 110M (40% smaller)
2. **Speed**: 60% faster inference
3. **Quality**: Retains 97% of BERT's performance
4. **Memory**: Fits on GPU with other services
5. **Availability**: Easy to use with Hugging Face transformers

### Why Mahalanobis Distance?

**Alternative**: Euclidean distance, cosine similarity only

**Chosen**: Mahalanobis distance for statistical detector

**Rationale**:
1. **Correlation aware**: Accounts for feature dependencies
2. **Scale invariant**: Works regardless of feature scales
3. **Gaussian assumption**: Statistical detector features are roughly Gaussian
4. **Interpretable**: "How many standard deviations from centroid?"

### Why Prototypical Learning?

**Alternative**: Fine-tune classifier on each tool

**Chosen**: Prototypical networks (compute class centroids)

**Rationale**:
1. **Few-shot friendly**: Works with limited training data
2. **No training required**: Just compute centroids
3. **Easy updates**: Add new samples by updating centroids
4. **Interpretable**: "How similar to prototype?"

---

## Data Flow & Request Processing

### Complete Request Lifecycle


1. **Client Request**

   * Client sends a JSON-RPC POST request: `{"jsonrpc":"2.0","method":"tools/call","params":{...},"id":1}`

2. **FastAPI Handler (main.py)**

   * Parses the JSON-RPC request
   * Validates its structure
   * Extracts the tool name and arguments

3. **Security Screening (detector.py)**

   * Flattens the payload (e.g., `tool_name:read_file|path:../../../etc/passwd`)
   * Runs a rule-based check (fast path); if a disallowed pattern matches, returns *ATTACK* immediately
   * If rule-based checks pass, runs ML detectors in parallel:

     * Statistical detector (Mahalanobis distance)
     * Semantic detector (embedding similarity)
     * MAML-based adapted classifier
   * Ensemble model computes combined benign and attack scores
   * If `(benign_score - attack_score) < threshold`, classification is *ATTACK*

4. **Decision Path**

   * **Allowed:** Forward request to tool via `RequestForwarder` (POST to tool endpoint)
   * **Blocked:** Return JSON-RPC error: `{"error":{"code":-32000,"message":"Security violation","data":{"class":"attack"}}}`

5. **Audit Logging (utils.py)**

   * Logs structured event: timestamp, tool name, classification result, confidence, decision, latency in milliseconds

---

## Configuration Reference

### Environment Variables

#### Bridge Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `DEBUG` | `false` | Enable debug mode |
| `MODEL_NAME` | `distilbert-base-uncased` | Embedding model |
| `DETECTOR_SIGMA` | `3.0` | Detection threshold (sigma rule) |
| `MCP_SERVERS` | (see compose) | Comma-separated tool server URLs |

#### Model Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `RESEARCH_DATA_PATH` | `/app/research_data` | Training data directory |
| `TRAINING_DATA_FILE` | `training_dataset.json` | Training data filename |
| `SEMANTIC_MODEL_PATH` | `/app/trained_models/semantic_model.pt` | Semantic model |
| `STATISTICAL_MODEL_PATH` | `/app/trained_models/statistical_model.pt` | Statistical model |
| `MAML_MODEL_PATH` | `/app/trained_models/maml_model.pt` | MAML model |
| `AUDIT_LOG_PATH` | `/app/research_data/runtime_audit.jsonl` | Audit log file |

#### MAML Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MAML_ENABLED` | `false` | Enable MAML detector |
| `MAML_META_LR` | `0.001` | Meta-learning rate |
| `MAML_INNER_LR` | `0.01` | Task adaptation rate |
| `MAML_ADAPTATION_STEPS` | `5` | Gradient steps for adaptation |
| `MAML_FIRST_ORDER` | `true` | Use first-order MAML |
| `MAML_SHOTS` | `5` | Examples per class |
| `MAML_HIDDEN_DIM` | `256` | Classifier hidden size |
| `MAML_CONFIDENCE_THRESHOLD` | `0.6` | Minimum confidence |
| `MAML_NUM_META_EPOCHS` | `100` | Meta-training epochs |

#### LLM Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MODEL_PATH` | `/app/models/llama-2-7b.gguf` | Local model path |
| `LLM_N_GPU_LAYERS` | `-1` | GPU layers (-1 = all) |
| `LLM_N_CTX` | `4096` | Context window |
| `LLM_CHAT_FORMAT` | `llama-2` | Chat template format |
| `CLOUD_LLM_PROVIDER` | `openai` | Cloud provider |
| `CLOUD_OPENAI_API_KEY` | | OpenAI API key |
| `CLOUD_GOOGLE_API_KEY` | | Google API key |

#### Tool Configuration

| Variable | Prefix | Description |
|----------|--------|-------------|
| `db_path` | `SQL_` | SQLite database path |
| `safe_mode` | `FETCH_`/`MEMORY_` | Enable security restrictions |
| `storage_path` | `MEMORY_` | Knowledge graph storage |
| `allowed_paths` | `FS_` | Allowed filesystem paths |

---

## Deployment & Operations

### Docker Compose Services

```yaml
services:
  mcp-bridge:         # Security proxy (port 8000)
  tool-filesystem:    # Filesystem tool
  tool-sqlite:        # Database tool
  tool-time:          # Time tool
  tool-fetch:         # URL fetching tool
  tool-memory:        # Knowledge graph tool
  custom-llm:         # Local LLM (port 8080)
  cloud-llm:          # Cloud LLM adapter (port 8081)
  mcp-client:         # Testing client
```

### Starting the System

```bash
# Build and start all services
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f mcp-bridge

# Restart after code changes
docker compose restart mcp-bridge
```

### Health Checks

```bash
# Bridge health
curl http://localhost:8000/health

# Test MCP handshake
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"clientInfo":{"name":"test","version":"1.0"}},"id":1}'

# List available tools
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### Model Retraining

```bash
# Delete cached models
rm research/trained_models/*.pt

# Restart bridge (will retrain from training_dataset.json)
docker compose restart mcp-bridge

# Or train manually
python research/tools/train_models.py
python research/tools/train_models.py --maml --maml-epochs 100
```

---

## Testing & Evaluation

### Quick Test

```bash
# Test benign request
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}},"id":1}'

# Test attack (should be blocked)
curl -X POST http://localhost:8000/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../etc/passwd"}},"id":1}'
```

### Load Testing

```bash
docker exec -it mcp-client python traffic_generator.py \
  --samples 100 \
  --malicious-ratio 0.25 \
  --concurrency 10
```

### Interactive Testing

```bash
docker exec -it mcp-client python agent.py
```

### Latency Benchmarking

```bash
docker exec -it mcp-client python latency_test.py
```

### Evaluation Notebooks

```bash
cd research/notebooks
jupyter notebook

# Open model_comparisons.ipynb for full evaluation
```

---

## API Reference

### JSON-RPC Endpoint

**URL**: `POST /jsonrpc` or `POST /`

**Request Format**:
```json
{
  "jsonrpc": "2.0",
  "method": "<method_name>",
  "params": { ... },
  "id": "<request_id>"
}
```

### MCP Methods

#### initialize

Handshake with capability negotiation.

```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": {
      "name": "test-client",
      "version": "1.0.0"
    },
    "capabilities": {}
  },
  "id": 1
}
```

#### tools/list

List available tools with pagination.

```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {
    "cursor": null  // Optional pagination cursor
  },
  "id": 1
}
```

#### tools/call

Execute a tool (security screened).

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "README.md"
    }
  },
  "id": 1
}
```

### Response Formats

#### Success

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {"type": "text", "text": "..."}
    ],
    "isError": false
  },
  "id": 1
}
```

#### Security Block

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Security violation: Request blocked",
    "data": {
      "class": "attack",
      "confidence": 0.95,
      "reason": "Rule match: path_traversal"
    }
  },
  "id": 1
}
```

---

## Appendix: Training Data Format

```json
{
  "read_file": {
    "benign": [
      "{\"path\": \"README.md\"}",
      "{\"path\": \"docs/guide.txt\"}",
      "{\"path\": \"./data/config.json\"}"
    ],
    "attack": [
      "{\"path\": \"../../../etc/passwd\"}",
      "{\"path\": \"$(cat /etc/shadow)\"}",
      "{\"path\": \"file:///etc/passwd\"}"
    ]
  },
  "read_query": {
    "benign": [
      "{\"query\": \"SELECT * FROM products WHERE id = 5\"}",
      "{\"query\": \"SELECT name, price FROM items LIMIT 10\"}"
    ],
    "attack": [
      "{\"query\": \"SELECT * FROM users WHERE id = 1 OR '1'='1'\"}",
      "{\"query\": \"'; DROP TABLE users; --\"}"
    ]
  }
}
```
