import logging

logger = logging.getLogger(__name__)

class EDRMonitor:
    """
    Simulates a runtime monitor that enforces detection rules.
    """
    
    def __init__(self):
        self.active_rules = []
        self.logs = []
        
    def load_rules(self, rules):
        """Load detection rules into engine"""
        self.active_rules = rules
        logger.info(f"EDR Monitor loaded {len(rules)} rules.")
        
    def check_ioctl(self, ioctl_code_str):
        """
        Simulate an IOCTL request and check against rules.
        
        Args:
            ioctl_code_str (str): Hex string of IOCTL, e.g. "0x222003"
            
        Returns:
            dict: Result {allowed: bool, action: str, rule: dict}
        """
        # Normalize input
        if isinstance(ioctl_code_str, int):
            ioctl_code_str = hex(ioctl_code_str)
            
        ioctl_code_str = ioctl_code_str.lower().strip()
        
        for rule in self.active_rules:
            # Check if rule targets IOCTL
            target = rule.get("target_ioctl")
            if target and target.lower() == ioctl_code_str:
                
                # Match found!
                action = rule.get("action", "ALERT")
                severity = rule.get("severity", "INFO")
                
                log_entry = {
                    "timestamp": "Now",
                    "event": "IOCTL_REQUEST",
                    "code": ioctl_code_str,
                    "result": action,
                    "rule_id": rule.get("id"),
                    "severity": severity
                }
                self.logs.append(log_entry)
                
                if action == "BLOCK":
                    return {"allowed": False, "action": "BLOCK", "rule": rule}
                else:
                    return {"allowed": True, "action": "ALERT", "rule": rule}
                    
        # No rule matched
        return {"allowed": True, "action": "ALLOW", "rule": None}
        
    def get_logs(self):
        return self.logs
    
    def clear_logs(self):
        self.logs = []
