import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

# Vulnerability patterns library
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*\+.*(?:request|input|param|user_input)',
        'severity': 'HIGH',
        'fix_template': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'cwe': 'CWE-89'
    },
    'hardcoded_secrets': {
        'pattern': r'(?:api_key|password|secret|token|apikey|api-key|SECRET_KEY|MONGODB_URI|DATABASE_URL)\s*=\s*["\'][^"\'\n]{8,}["\']',
        'severity': 'CRITICAL',
        'fix_template': 'Use environment variables: api_key = os.getenv("API_KEY")',
        'cwe': 'CWE-798'
    },
    'command_injection': {
        'pattern': r'(?:exec|eval|system|subprocess\.call|os\.system)\s*\([^)]*(?:request|input|user)',
        'severity': 'CRITICAL',
        'fix_template': 'Use subprocess with shell=False: subprocess.run([command], shell=False)',
        'cwe': 'CWE-78'
    },
    'xss': {
        'pattern': r'(?:innerHTML|document\.write|outerHTML)\s*=.*(?:request|input|param|user)',
        'severity': 'HIGH',
        'fix_template': 'Sanitize input: element.textContent = userInput',
        'cwe': 'CWE-79'
    },
    'path_traversal': {
        'pattern': r'(?:open|readFile|require)\s*\([^)]*(?:\.\./|request|input)',
        'severity': 'HIGH',
        'fix_template': 'Validate paths: filepath = os.path.join(safe_dir, os.path.basename(user_input))',
        'cwe': 'CWE-22'
    },
    'weak_jwt': {
        'pattern': r'jwt\.decode\s*\([^)]*verify_signature["\']?\s*:\s*False',
        'severity': 'CRITICAL',
        'fix_template': 'Always verify JWT signatures: jwt.decode(token, key, algorithms=["HS256"])',
        'cwe': 'CWE-347'
    },
    'mongodb_injection': {
        'pattern': r'(?:find|find_one|update|delete)\s*\(\s*\{[^}]*:\s*(?:username|password|user_input|request)',
        'severity': 'HIGH',
        'fix_template': 'Sanitize MongoDB queries: db.find({"username": {"$eq": username}})',
        'cwe': 'CWE-943'
    }
}

@dataclass
class Vulnerability:
    type: str
    severity: str
    line_number: int
    code_snippet: str
    fix_suggestion: str
    confidence: float
    cwe_id: str

class SecurityAgent:
    def __init__(self):
        self.patterns = VULNERABILITY_PATTERNS
        self.scan_history = []
        
    def analyze_code_diff(self, diff: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = diff.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip diff metadata
            if line.startswith(('+++', '---', '@@')):
                continue
                
            # Only analyze added lines
            if line.startswith('+'):
                code_line = line[1:]  # Remove the +
                
                for vuln_type, config in self.patterns.items():
                    if re.search(config['pattern'], code_line, re.IGNORECASE):
                        vuln = Vulnerability(
                            type=vuln_type,
                            severity=config['severity'],
                            line_number=line_num,
                            code_snippet=code_line.strip(),
                            fix_suggestion=config['fix_template'],
                            confidence=0.85,
                            cwe_id=config['cwe']
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[Vulnerability]) -> Dict:
        if not vulnerabilities:
            return {
                'status': 'PASS',
                'message': '✅ No security vulnerabilities detected!',
                'score': 100
            }
        
        # Calculate security score
        severity_weights = {'CRITICAL': 30, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5}
        total_penalty = sum(severity_weights.get(v.severity, 5) for v in vulnerabilities)
        score = max(0, 100 - total_penalty)
        
        return {
            'status': 'FAIL',
            'score': score,
            'vulnerabilities': [
                {
                    'type': v.type.replace('_', ' ').title(),
                    'severity': v.severity,
                    'line': v.line_number,
                    'code': v.code_snippet,
                    'fix': v.fix_suggestion,
                    'cwe': v.cwe_id
                } for v in vulnerabilities
            ]
        }
    
    def analyze_with_context(self, code: str, context_before: str, context_after: str) -> List[Vulnerability]:
        """Enhanced analysis with code context"""
        # Implementation for context-aware analysis
        full_context = f"{context_before}\n{code}\n{context_after}"
        return self.analyze_code_diff(full_context, "contextual_analysis")
    
    def suggest_auto_fix(self, vulnerability: Vulnerability, code_context: str) -> str:
        """Generate actual fix code"""
        fixes = {
            'sql_injection': lambda code: re.sub(
                r'"SELECT.*?" \+ (\w+)',
                r'"SELECT * FROM users WHERE id = ?", (\1,)',
                code
            ),
            'hardcoded_secrets': lambda code: re.sub(
                r'(\w+)\s*=\s*["\'][^"\']+["\']',
                r'\1 = os.getenv("\1".upper())',
                code
            ),
            'command_injection': lambda code: re.sub(
                r'os\.system\(["\'].*["\'] \+ (\w+)\)',
                r'subprocess.run([\1], shell=False)',
                code
            ),
            'xss': lambda code: re.sub(
                r'innerHTML\s*=\s*(.+)',
                r'textContent = \1',
                code
            )
        }
        
        if vulnerability.type in fixes:
            return fixes[vulnerability.type](code_context)
        return vulnerability.fix_suggestion