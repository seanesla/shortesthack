"""
Security Agent - Enhanced vulnerability detection patterns
Improved to catch modern JavaScript/TypeScript patterns
"""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Enhanced vulnerability patterns library
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        # Updated to catch template literals, concatenation, and string interpolation
        'patterns': [
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*\+\s*[\'"`]?\s*\+?\s*(?:request|input|param|user|req\.|params|query|body|data)',
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)[^"\'`]*\$\{[^}]*(?:user|input|param|req|query|body)',
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)[^"\'`]*[\'"`]\s*\+\s*(?:user|input|param|req|query)',
            r'query\s*=\s*[\'"`]?(SELECT|INSERT|UPDATE|DELETE|DROP).*[\'"`]?\s*[\+\$]',
        ],
        'severity': 'HIGH',
        'fix_template': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'cwe': 'CWE-89'
    },
    'hardcoded_secrets': {
        # Comprehensive patterns for various secret formats
        'patterns': [
            r'(?:api[_-]?key|apikey|api[_-]?secret|key)\s*[:=]\s*[\'"`]([A-Za-z0-9_\-]{10,})[\'"`]',
            r'(?:password|passwd|pwd)\s*[:=]\s*[\'"`]([^\'"`]{8,})[\'"`]',
            r'(?:secret|token|auth[_-]?token|access[_-]?token)\s*[:=]\s*[\'"`]([A-Za-z0-9_\-]{10,})[\'"`]',
            r'(?:SECRET_KEY|JWT_SECRET|ENCRYPTION_KEY)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'(?:DATABASE_URL|MONGODB_URI|POSTGRES_URI|MYSQL_URI)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'sk[_-](?:test|live|prod)[_-][A-Za-z0-9]{24,}',
            r'(?:aws|azure|gcp)[_-]?(?:access|secret)[_-]?(?:key|id)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'JWT_SECRET\s*=\s*[\'"`][^\'"`]+[\'"`]',  # Specific pattern for JWT_SECRET
        ],
        'severity': 'CRITICAL',
        'fix_template': 'Use environment variables: api_key = os.getenv("API_KEY")',
        'cwe': 'CWE-798'
    },
    'command_injection': {
        # Improved to catch indirect command injection
        'patterns': [
            r'(?:exec|eval|system|spawn|execSync|execFile)\s*\([^)]*[\'"`\$\+].*(?:user|input|param|req|query|body)',
            r'(?:exec|eval|system|spawn).*\$\{[^}]*(?:user|input|param|req|query)',
            r'child_process\.[a-z]+\s*\([^)]*(?:user|input|param|req)',
            r'os\.(?:system|popen|exec[a-z]*)\s*\([^)]*[\$\+`]',
            r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*(?:user|input)',
            r'(?:command|cmd)\s*=\s*[\'"`].*\$\{[^}]*\}.*[\'"`]',
            r'(?:command|cmd)\s*=\s*.*\+\s*(?:user|input|param)',
            r'exec\s*\(\s*(?:command|cmd)',  # exec(command) pattern
        ],
        'severity': 'CRITICAL',
        'fix_template': 'Use subprocess with shell=False: subprocess.run([command], shell=False)',
        'cwe': 'CWE-78'
    },
    'xss': {
        # Cross-site scripting patterns
        'patterns': [
            r'(?:innerHTML|outerHTML|document\.write)\s*[=\+]+.*(?:request|input|param|user|req\.|data)',
            r'(?:innerHTML|outerHTML)\s*=.*\$\{[^}]*(?:user|input|param)',
            r'dangerouslySetInnerHTML\s*=\s*\{\s*__html:.*(?:user|input|param)',
            r'v-html\s*=\s*[\'"`].*(?:user|input|param)',
            r'ng-bind-html.*=.*(?:user|input|param)',
        ],
        'severity': 'HIGH',
        'fix_template': 'Sanitize input: element.textContent = userInput',
        'cwe': 'CWE-79'
    },
    'path_traversal': {
        # Enhanced path traversal detection
        'patterns': [
            r'(?:readFile|readFileSync|createReadStream|open)\s*\([^)]*[\'"`]?[^)]*\$\{[^}]*(?:user|input|file|path|filename)',
            r'(?:readFile|readFileSync|open)\s*\([\'"`][^\'"`]*(?:\.\./|\$\{)',
            r'[\'"`][/\\](?:uploads|files|data)[/\\][^\'"`]*\$\{[^}]*(?:user|file|path)',
            r'require\s*\([^)]*(?:user|input|param)',
        ],
        'severity': 'HIGH',
        'fix_template': 'Validate paths: filepath = path.join(SAFE_DIR, path.basename(userInput))',
        'cwe': 'CWE-22'
    },
    'weak_jwt': {
        # JWT vulnerability patterns
        'patterns': [
            r'jwt\.decode\s*\([^)]*verify[_-]?signature[\'"`]?\s*:\s*(?:False|false)',
            r'jwt\.decode\s*\([^)]*\{\s*complete\s*:\s*true\s*\}',
            r'jsonwebtoken\.decode\s*\([^)]*,\s*null\s*\)',
            r'JWT\.decode\s*\([^)]*verify\s*:\s*false',
        ],
        'severity': 'CRITICAL',
        'fix_template': 'Always verify JWT signatures: jwt.decode(token, key, algorithms=["HS256"])',
        'cwe': 'CWE-347'
    },
    'mongodb_injection': {
        # MongoDB NoSQL injection
        'patterns': [
            r'(?:find|findOne|update|delete|aggregate)\s*\(\s*\{[^}]*:\s*(?:req\.|request|body|params|query)',
            r'(?:find|findOne)\s*\(\s*\{[^}]*\$(?:where|regex|ne|gt|lt)',
            r'\$where.*(?:user|input|param|req)',
            r'collection\.[a-z]+\s*\(\s*\{[^}]*:\s*[^}]*(?:user|input|param)',
        ],
        'severity': 'HIGH',
        'fix_template': 'Sanitize MongoDB queries: db.find({"username": {"$eq": username}})',
        'cwe': 'CWE-943'
    },
    'eval_usage': {
        # Dangerous eval and similar functions
        'patterns': [
            r'eval\s*\([^)]*(?:user|input|param|req|request|body|query)',
            r'eval\s*\([^)]*[\'"`].*\+',
            r'eval\s*\([^)]+\)',  # Any eval usage
            r'return\s+eval\s*\(',  # Return eval pattern
            r'new\s+Function\s*\([^)]*(?:user|input|param)',
            r'setTimeout\s*\([\'"`].*(?:user|input|param)',
            r'setInterval\s*\([\'"`].*(?:user|input|param)',
            r'vm\.run[a-zA-Z]*\s*\([^)]*(?:user|input)',
        ],
        'severity': 'CRITICAL',
        'fix_template': 'Avoid eval(). Use safer alternatives like JSON.parse() or specific parsing functions',
        'cwe': 'CWE-95'
    },
    'insecure_crypto': {
        # Weak or deprecated cryptography
        'patterns': [
            r'crypto\.createCipher\s*\(',
            r'md5\s*\([^)]*(?:password|secret)',
            r'sha1\s*\([^)]*(?:password|secret)',
            r'Math\.random\s*\(\s*\).*(?:token|secret|key|password)',
            r'DES|3DES|RC4|Blowfish',
        ],
        'severity': 'HIGH',
        'fix_template': 'Use strong cryptography: crypto.createCipheriv() with AES-256-GCM',
        'cwe': 'CWE-327'
    },
    'ssrf': {
        # Server-Side Request Forgery
        'patterns': [
            r'(?:fetch|axios|request|http\.get)\s*\([^)]*(?:user|input|param|req\.|url)',
            r'(?:fetch|axios)\s*\([\'"`]?\s*\$\{[^}]*(?:user|input|url)',
            r'urllib\.request\.urlopen\s*\([^)]*(?:user|input)',
        ],
        'severity': 'HIGH',
        'fix_template': 'Validate and whitelist URLs before making requests',
        'cwe': 'CWE-918'
    }
}

@dataclass
class Vulnerability:
    """Represents a detected security vulnerability"""
    type: str
    severity: str
    line_number: int
    code_snippet: str
    fix_suggestion: str
    confidence: float
    cwe_id: str
    pattern_matched: str = ""

class SecurityAgent:
    """Enhanced security analysis agent with improved pattern matching"""
    
    def __init__(self):
        self.patterns = VULNERABILITY_PATTERNS
        self.scan_history = []
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance"""
        self.compiled_patterns = {}
        for vuln_type, config in self.patterns.items():
            if 'patterns' in config:
                self.compiled_patterns[vuln_type] = [
                    re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                    for pattern in config['patterns']
                ]
            else:
                # Backward compatibility for single pattern
                self.compiled_patterns[vuln_type] = [
                    re.compile(config['pattern'], re.IGNORECASE | re.MULTILINE)
                ]
    
    def analyze_code_diff(self, diff: str, filename: str) -> List[Vulnerability]:
        """Analyze code diff for security vulnerabilities"""
        vulnerabilities = []
        lines = diff.split('\n')
        
        # Track context for better analysis
        recent_lines = []
        
        for line_num, line in enumerate(lines, 1):
            # Skip diff metadata
            if line.startswith(('+++', '---', '@@')):
                continue
            
            # Store recent context
            if line.startswith('+'):
                code_line = line[1:]  # Remove the +
                recent_lines.append((line_num, code_line))
                
                # Keep only last 5 lines for context
                if len(recent_lines) > 5:
                    recent_lines.pop(0)
                
                # Check for vulnerabilities
                for vuln in self._check_line_for_vulnerabilities(
                    code_line, line_num, recent_lines
                ):
                    # Avoid duplicate detections
                    if not any(
                        v.line_number == vuln.line_number and 
                        v.type == vuln.type 
                        for v in vulnerabilities
                    ):
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_line_for_vulnerabilities(
        self, 
        code_line: str, 
        line_num: int, 
        context: List[Tuple[int, str]]
    ) -> List[Vulnerability]:
        """Check a single line for all vulnerability patterns"""
        vulnerabilities = []
        
        # Build context string for better detection
        context_str = '\n'.join([line for _, line in context])
        
        for vuln_type, patterns in self.compiled_patterns.items():
            config = self.patterns[vuln_type]
            
            for pattern in patterns:
                # Check current line
                if pattern.search(code_line):
                    vulnerabilities.append(self._create_vulnerability(
                        vuln_type, config, line_num, code_line.strip(), str(pattern.pattern)
                    ))
                    break  # Avoid multiple matches for same vulnerability type
                
                # Also check in context for multi-line patterns
                if len(context) > 1 and pattern.search(context_str):
                    # Find which line in context matches
                    for ctx_line_num, ctx_line in context:
                        if pattern.search(ctx_line):
                            vulnerabilities.append(self._create_vulnerability(
                                vuln_type, config, ctx_line_num, ctx_line.strip(), str(pattern.pattern)
                            ))
                            break
                    break
        
        return vulnerabilities
    
    def _create_vulnerability(
        self, 
        vuln_type: str, 
        config: Dict, 
        line_num: int, 
        code_snippet: str,
        pattern: str
    ) -> Vulnerability:
        """Create a vulnerability object"""
        # Calculate confidence based on pattern specificity
        confidence = 0.95 if len(code_snippet) > 50 else 0.85
        
        # Special handling for SQL injection in template literals
        if vuln_type == 'sql_injection' and '${' in code_snippet:
            vuln_type = 'sql_injection_template_literal'
        
        return Vulnerability(
            type=vuln_type,
            severity=config['severity'],
            line_number=line_num,
            code_snippet=code_snippet,
            fix_suggestion=config['fix_template'],
            confidence=confidence,
            cwe_id=config['cwe'],
            pattern_matched=pattern
        )
    
    def generate_report(self, vulnerabilities: List[Vulnerability]) -> Dict:
        """Generate a comprehensive security report"""
        if not vulnerabilities:
            return {
                'status': 'PASS',
                'message': '✅ No security vulnerabilities detected!',
                'score': 100,
                'vulnerabilities': []
            }
        
        # Calculate security score
        severity_weights = {
            'CRITICAL': 30,
            'HIGH': 20,
            'MEDIUM': 10,
            'LOW': 5
        }
        
        total_penalty = sum(
            severity_weights.get(v.severity, 5) 
            for v in vulnerabilities
        )
        score = max(0, 100 - total_penalty)
        
        # Group vulnerabilities by type
        vuln_summary = {}
        for v in vulnerabilities:
            vuln_type = v.type.replace('_', ' ').title()
            if vuln_type not in vuln_summary:
                vuln_summary[vuln_type] = 0
            vuln_summary[vuln_type] += 1
        
        return {
            'status': 'FAIL',
            'score': score,
            'summary': vuln_summary,
            'total_issues': len(vulnerabilities),
            'critical_issues': len([v for v in vulnerabilities if v.severity == 'CRITICAL']),
            'high_issues': len([v for v in vulnerabilities if v.severity == 'HIGH']),
            'vulnerabilities': [
                {
                    'type': v.type.replace('_', ' ').title(),
                    'severity': v.severity,
                    'line': v.line_number,
                    'code': v.code_snippet,
                    'fix': v.fix_suggestion,
                    'cwe': v.cwe_id,
                    'confidence': v.confidence
                } for v in vulnerabilities
            ]
        }
    
    def analyze_file(self, file_content: str, filename: str) -> List[Vulnerability]:
        """Analyze an entire file by converting it to diff format"""
        # Convert to diff format for compatibility
        diff_lines = [f"+{line}" for line in file_content.split('\n')]
        diff_content = '\n'.join(diff_lines)
        return self.analyze_code_diff(diff_content, filename)