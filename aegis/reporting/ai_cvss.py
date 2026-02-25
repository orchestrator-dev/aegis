from aegis.core.models import Finding

class AICVSSScorer:
    """
    Calculates an AI-specific Common Vulnerability Scoring System metric.
    This is a simplified mock adapting standard CVSS 3.1 to our model.
    """
    
    @staticmethod
    def calculate_score(finding: Finding) -> float:
        """
        Produce a score from 0.0 to 10.0 based on Severity and Maestro Layer.
        """
        base_scores = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 0.0
        }
        
        score = base_scores.get(finding.severity.value, 0.0)
        
        # Adjust score based on layer
        # Code execution (L3_ACTION) or Systemic (L7) might bump the decimal up
        if finding.maestro_layer in ["L3", "L7"]:
            score = min(10.0, score + 0.5)
            
        return score
