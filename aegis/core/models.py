from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
import datetime

class OWASPAgenticCategory(str, Enum):
    ASI01_GOAL_HIJACK = "ASI01"
    ASI02_TOOL_MISUSE = "ASI02"
    ASI03_PRIVILEGE_ABUSE = "ASI03"
    ASI04_SUPPLY_CHAIN = "ASI04"
    ASI05_CODE_EXECUTION = "ASI05"
    ASI06_MEMORY_POISONING = "ASI06"
    ASI07_INTER_AGENT = "ASI07"
    ASI08_CASCADING = "ASI08"
    ASI09_TRUST_EXPLOIT = "ASI09"
    ASI10_ROGUE_AGENT = "ASI10"

class OWASPLLMCategory(str, Enum):
    LLM01_PROMPT_INJECTION = "LLM01:2025"
    LLM02_SENSITIVE_INFO = "LLM02:2025"
    LLM03_SUPPLY_CHAIN = "LLM03:2025"
    LLM04_DATA_MODEL_POISON = "LLM04:2025"
    LLM05_IMPROPER_OUTPUT = "LLM05:2025"
    LLM06_EXCESSIVE_AGENCY = "LLM06:2025"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07:2025"
    LLM08_VECTOR_EMBEDDING = "LLM08:2025"
    LLM09_MISINFORMATION = "LLM09:2025"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10:2025"

class MAESTROLayer(str, Enum):
    L0_SUPPLY_CHAIN = "L0"
    L1_INPUT = "L1"
    L2_DATA_MEMORY = "L2"
    L3_ACTION = "L3"
    L4_AUTHORIZATION = "L4"
    L5_COMMUNICATION = "L5"
    L6_MONITORING = "L6"
    L7_SYSTEMIC = "L7"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ToolDefinition(BaseModel):
    name: str
    description: str
    parameters: Dict
    required_permissions: List[str] = []
    is_destructive: bool = False
    requires_hitl: bool = False  # Human-in-the-Loop

class AgentManifest(BaseModel):
    """Complete description of an agent's capabilities"""
    agent_id: str
    name: str
    description: str
    agent_framework: Optional[str] = None  # e.g., LangChain, AutoGen, Custom
    transport_protocol: str = "REST"  # e.g., REST, WebSocket, gRPC, MCP
    llm_provider: str
    llm_model: str
    system_prompt: Optional[str] = None
    tools: List[ToolDefinition] = []
    memory_type: Optional[str] = None  # None, "short-term", "long-term", "vector-db"
    vector_db_config: Optional[Dict] = None
    permissions: List[str] = []
    hitl_enabled: bool = False
    rate_limits: Optional[Dict] = None
    max_cost_usd: Optional[float] = None  # Budget for testing
    token_budget: Optional[int] = None
    input_filters: List[str] = []
    output_filters: List[str] = []

class ThreatModel(BaseModel):
    """STRIDE-AI based threat model"""
    target_system: str
    maestro_layers: List[MAESTROLayer]
    attack_surface: Dict[str, List[str]]
    trust_boundaries: List[str]
    data_flows: List[Dict]
    identified_threats: List[Dict]
    risk_score: float
    
class AttackPath(BaseModel):
    """Chain-of-attack representation"""
    path_id: str
    start_layer: MAESTROLayer
    end_layer: MAESTROLayer
    steps: List[Dict]
    exploitability_score: float
    impact_score: float
    description: str

class Finding(BaseModel):
    """Standardized security finding"""
    finding_id: str = Field(default_factory=lambda: f"AEGIS-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
    title: str
    description: str
    severity: Severity
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    
    # Taxonomy mappings
    owasp_agentic: Optional[OWASPAgenticCategory] = None
    owasp_llm: Optional[OWASPLLMCategory] = None
    maestro_layer: MAESTROLayer
    
    # Attack path
    attack_path: Optional[AttackPath] = None
    
    # Evidence
    evidence: Dict = {}
    reproduction_steps: List[str] = []
    
    # Remediation
    remediation: str
    references: List[str] = []
    
    # Metadata
    discovered_at: datetime.datetime = Field(default_factory=datetime.datetime.now)
    scanner_module: str
    target_system: str

class TestCase(BaseModel):
    """Adversarial test case"""
    test_id: str
    category: str
    prompt: str
    expected_behavior: str
    attack_type: str
    owasp_mapping: List[str]
    metadata: Dict = {}

class ScanResult(BaseModel):
    """Complete scan output"""
    scan_id: str
    target: AgentManifest
    started_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    findings: List[Finding] = []
    tests_run: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    overall_risk_score: float = 0.0
    executive_summary: str = ""
