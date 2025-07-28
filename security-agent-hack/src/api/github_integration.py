from github import Github
import os
from typing import List, Dict
from dotenv import load_dotenv

load_dotenv()

class GitHubIntegration:
    def __init__(self):
        token = os.getenv("GITHUB_TOKEN")
        if token and token != "your_github_token_here":
            self.client = Github(token)
            self.enabled = True
        else:
            self.client = None
            self.enabled = False
    
    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get the actual diff from a pull request"""
        if not self.enabled:
            print("WARNING: GitHub token not configured - using demo data")
            return self.get_mock_diff()
        
        try:
            print(f"Fetching real PR diff from {repo_name} PR #{pr_number}")
            repo = self.client.get_repo(repo_name)
            pr = repo.get_pull(pr_number)
            
            # Get ALL file changes with proper diff format
            full_diff = ""
            files = pr.get_files()
            
            for file in files:
                if file.patch:  # patch contains the diff
                    full_diff += f"\n+++ b/{file.filename}\n"
                    full_diff += f"@@ -{file.deletions} +{file.additions} @@\n"
                    full_diff += file.patch + "\n"
            
            print(f"Successfully fetched {len(list(files))} files from PR")
            return full_diff
            
        except Exception as e:
            print(f"GitHub API error: {e}")
            print("Falling back to demo data")
            return self.get_mock_diff()
    
    def post_review_comment(self, repo_name: str, pr_number: int, report: Dict):
        """Post security review as PR comment"""
        if not self.enabled:
            print("GitHub integration not enabled - no token provided")
            return
            
        try:
            repo = self.client.get_repo(repo_name)
            pr = repo.get_pull(pr_number)
            
            # Format comment
            comment = self._format_comment(report)
            pr.create_issue_comment(comment)
        except Exception as e:
            print(f"Error posting comment: {e}")
    
    def _format_comment(self, report: Dict) -> str:
        if report['status'] == 'PASS':
            return "## 🔒 Security Review: PASSED\n\n✅ No security vulnerabilities detected!"
        
        comment = f"## 🚨 Security Review: FAILED (Score: {report['score']}/100)\n\n"
        comment += "### Vulnerabilities Found:\n\n"
        
        for vuln in report['vulnerabilities']:
            comment += f"#### {vuln['type']} ({vuln['severity']})\n"
            comment += f"- **Line**: {vuln['line']}\n"
            comment += f"- **Code**: `{vuln['code']}`\n"
            comment += f"- **Fix**: {vuln['fix']}\n"
            comment += f"- **CWE**: {vuln['cwe']}\n\n"
        
        return comment
    
    def get_mock_diff(self) -> str:
        """Return mock diff for demo purposes"""
        return '''+++ b/demo.py
+def login(username, password):
+    query = "SELECT * FROM users WHERE username = '" + username + "'"
+    api_key = "sk-prod-1234567890abcdef"
+    os.system("echo Welcome " + username)
+    return {"token": api_key}'''