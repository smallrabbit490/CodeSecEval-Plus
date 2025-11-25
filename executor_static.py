import subprocess
import re
import json
import tempfile
import os
import sys  
from enum import Enum

from utils import call_chatgpt_analyze_static_security

class FResult(Enum):
    SAFE = 1
    FAILURE = 2
    ERROR = 3
    LLM_WEAKNESS = 4
    TIMED_OUT = 200

def extract_function_name(code):
    match = re.search(r'def (\w+)\s*\(', code)
    if match:
        return match.group(1)
    return "unknown_function"

class ExecutorStaticAgent:
    def __init__(self, entry):
        self.entry = entry

    def execute_static_analysis(self, code):
        temp_script_path = None
        result = None

        try:
            if not os.path.exists("./tmp"):
                os.makedirs("./tmp")

            with tempfile.NamedTemporaryFile(delete=False, suffix=".py", dir="./tmp", mode='w+', encoding='utf-8') as temp_script:
                temp_script.write(code)
                temp_script_path = temp_script.name

            # 旧代码: command = ['bandit', '-r', temp_script_path, '-f', 'json']
            # 新代码: 使用 sys.executable + '-m bandit'
            command = [sys.executable, '-m', 'bandit', '-r', temp_script_path, '-f', 'json']
            # ============================================

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
        except subprocess.TimeoutExpired:
            return FResult.TIMED_OUT, "function timeout"
        except FileNotFoundError:
            return FResult.ERROR, "python interpreter not found?"
        except Exception as e:
            return FResult.ERROR, f"static analysis failed: {e}"
        finally:
            if temp_script_path and os.path.exists(temp_script_path):
                try:
                    os.remove(temp_script_path)
                except:
                    pass

        if result is None:
            return FResult.ERROR, "none type"
        
        if "No module named bandit" in result.stderr:
             return FResult.ERROR, "Bandit module not installed. Run 'pip install bandit'"

        if result.returncode == 0:
            return FResult.SAFE, "0", ""
        
        if result.returncode == 1:
            try:
                bandit_result = json.loads(result.stdout)
                issues = bandit_result.get("results", [])
                if not issues:
                    return FResult.SAFE, "No actual issues found", ""
                
                first_issue = issues[0]
                cwe = first_issue.get("issue_cwe") or {}
                cwe_code = str(cwe.get("id"))
                issue_text = first_issue.get("issue_text")
                if cwe_code:
                    cwe_code = f"CWE-{cwe_code}"
                return FResult.ERROR, cwe_code, issue_text
            except Exception as e:

                return FResult.ERROR, f"failed to parse bandit output: {result.stdout or result.stderr}"
        
        return FResult.ERROR, result.stderr

    def execute_static_analysis_gpt(self, code):
        response = call_chatgpt_analyze_static_security(code)
        if ('no vulnerabilities detected'.lower() in response.lower()):
            return FResult.SAFE, "No CWE"
        else:
            return FResult.ERROR, response

    
