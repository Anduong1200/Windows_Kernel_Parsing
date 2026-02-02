import json
from datetime import datetime

class RuleGenerator:
    """
    Generates EDR detection signatures based on analysis security insights.
    """
    
    def __init__(self):
        self.rules = []
        
    def generate_rules(self, security_insights):
        """
        Convert analysis insights into detection rules.
        
        Args:
            security_insights (list): List of findings from TaintAnalysis/Heuristics
            
        Returns:
            list: List of generated rule dictionaries
        """
        self.rules = []
        
        for insight in security_insights:
            # Skip non-dict items (e.g., string summaries)
            if not isinstance(insight, dict):
                continue
                
            risk_score = insight.get("risk_score", 0)
            
            # Only create rules for actual risks
            if risk_score > 30:
                rule = self._create_rule(insight)
                if rule:
                    self.rules.append(rule)
                    
        return self.rules
        
    def _create_rule(self, insight):
        """Create a single rule from an insight"""
        risk_score = insight.get("risk_score", 0)
        
        # Determine Severity and Action
        if risk_score >= 80:
            severity = "CRITICAL"
            action = "BLOCK"
        elif risk_score >= 50:
            severity = "HIGH"
            action = "BLOCK"
        else:
            severity = "WARNING"
            action = "ALERT"
            
        # Extract indicators
        details = insight.get("description", "")
        # Heuristics to find IOCTLS or addresses in description
        # e.g. "Vulnerable usage in IOCTL 0x222003"
        ioctl_code = None
        import re
        match = re.search(r"IOCTL\s+(0x[0-9a-fA-F]+)", details)
        if match:
            ioctl_code = match.group(1)
            
        rule_name = f"Rule_{int(datetime.now().timestamp())}_{len(self.rules)}"
        
        rule = {
            "id": rule_name,
            "created_at": datetime.now().isoformat(),
            "severity": severity,
            "action": action,
            "target_ioctl": ioctl_code,
            "description": details,
            "detection_logic": "ioctl_match" if ioctl_code else "behavior_match"
        }
        
        return rule
        
    def export_rules(self, file_path):
        """Save rules to file"""
        with open(file_path, 'w') as f:
            json.dump(self.rules, f, indent=2)
