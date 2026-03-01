"""
G-03: Core threat modelling module — STRIDE-AI based threat model builder.
Generates an attack tree from an AgentManifest and returns a structured ThreatModel.
"""
from typing import List, Dict, Any
from datetime import datetime

from morpheus.core.models import AgentManifest, ThreatModel, MAESTROLayer, AttackPath


class ThreatModeler:
    """
    STRIDE-AI threat modelling engine.
    
    For each trust boundary in the AgentManifest, it:
    1. Identifies applicable MAESTRO layers
    2. Generates attack paths per STRIDE category
    3. Calculates a composite risk score
    """

    STRIDE_CATEGORIES = [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ]

    def build_threat_model(self, target: AgentManifest) -> ThreatModel:
        """Build a complete STRIDE-AI threat model for the target agent."""
        maestro_layers  = self._identify_maestro_layers(target)
        attack_surface  = self._map_attack_surface(target)
        trust_boundaries= self._identify_trust_boundaries(target)
        data_flows      = self._map_data_flows(target)
        threats         = self._generate_stride_threats(target, maestro_layers)
        risk_score      = self._calculate_risk_score(threats)

        return ThreatModel(
            target_system=target.name,
            maestro_layers=maestro_layers,
            attack_surface=attack_surface,
            trust_boundaries=trust_boundaries,
            data_flows=data_flows,
            identified_threats=threats,
            risk_score=risk_score,
        )

    def _identify_maestro_layers(self, target: AgentManifest) -> List[MAESTROLayer]:
        """Map agent capabilities to MAESTRO threat model layers."""
        layers = [MAESTROLayer.L1_INPUT]  # All agents get input layer

        if target.agent_framework:
            layers.append(MAESTROLayer.L0_SUPPLY_CHAIN)
        if target.memory_type:
            layers.append(MAESTROLayer.L2_DATA_MEMORY)
        if target.tools:
            layers.append(MAESTROLayer.L3_ACTION)
        if target.hitl_enabled or any(t.requires_hitl for t in target.tools):
            layers.append(MAESTROLayer.L4_AUTHORIZATION)
        if target.transport_protocol in ("REST", "WebSocket", "gRPC", "MCP"):
            layers.append(MAESTROLayer.L5_COMMUNICATION)

        return list(dict.fromkeys(layers))  # deduplicate preserving order

    def _map_attack_surface(self, target: AgentManifest) -> Dict[str, List[str]]:
        """Return a dict of attack surface area → vulnerable interfaces."""
        surface: Dict[str, List[str]] = {}
        if target.system_prompt:
            surface["system_prompt"] = ["prompt injection", "instruction override"]
        if target.tools:
            surface["tools"] = [t.name for t in target.tools]
        if target.memory_type:
            surface["memory"] = [target.memory_type]
        if target.vector_db_config:
            surface["vector_db"] = list(target.vector_db_config.keys())
        return surface

    def _identify_trust_boundaries(self, target: AgentManifest) -> List[str]:
        """Identify where data crosses trust boundaries."""
        boundaries = ["user → agent", f"agent → {target.llm_provider} API"]
        if target.tools:
            boundaries.append("agent → external tool")
        if target.memory_type in ("vector-db", "long-term"):
            boundaries.append("agent → memory store")
        return boundaries

    def _map_data_flows(self, target: AgentManifest) -> List[Dict[str, Any]]:
        """Map data flows between components."""
        flows = [
            {"from": "user", "to": "agent_input", "data": "user_message"},
            {"from": "agent_input", "to": target.llm_provider, "data": "prompt"},
            {"from": target.llm_provider, "to": "agent_output", "data": "completion"},
        ]
        for tool in target.tools:
            flows.append({
                "from": "agent", "to": f"tool:{tool.name}",
                "data": "tool_arguments", "is_destructive": tool.is_destructive
            })
        return flows

    def _generate_stride_threats(
        self, target: AgentManifest, layers: List[MAESTROLayer]
    ) -> List[Dict[str, Any]]:
        """Generate threat entries per STRIDE category per relevant layer."""
        threats = []
        for layer in layers:
            for stride in self.STRIDE_CATEGORIES:
                threat_id = f"T-{layer.value}-{stride[:3].upper()}"
                threats.append({
                    "id": threat_id,
                    "stride_category": stride,
                    "maestro_layer": layer.value,
                    "description": f"{stride} threat at layer {layer.value} for agent {target.name}",
                    "likelihood": self._estimate_likelihood(stride, target),
                    "impact": "HIGH" if layer in (MAESTROLayer.L3_ACTION, MAESTROLayer.L4_AUTHORIZATION) else "MEDIUM",
                })
        return threats

    def _estimate_likelihood(self, stride: str, target: AgentManifest) -> str:
        """Heuristic likelihood estimate based on agent configuration."""
        if stride in ("Tampering", "Information Disclosure") and not target.input_filters:
            return "HIGH"
        if stride == "Denial of Service" and not target.rate_limits:
            return "HIGH"
        if stride == "Elevation of Privilege" and target.permissions:
            return "MEDIUM"
        return "LOW"

    def _calculate_risk_score(self, threats: List[Dict]) -> float:
        """Compute a 0–10 risk score from the threat list."""
        high_count   = sum(1 for t in threats if t.get("likelihood") == "HIGH")
        medium_count = sum(1 for t in threats if t.get("likelihood") == "MEDIUM")
        return min(10.0, round(high_count * 0.8 + medium_count * 0.3, 2))
