import subprocess
import re
import json
import tempfile
import os 
from enum import Enum

from utils import call_chatgpt_analyze_static_security

class FResult(Enum):
    SAFE = 1  # validation returns okay
    FAILURE = 2  # validation contains error (something wrong with validation)
    ERROR = 3  # validation returns a potential error (look into)
    LLM_WEAKNESS = (
        4  # the generated input is ill-formed due to the weakness of the language model
    )
    TIMED_OUT = 10  # timed out, can be okay in certain targets

def extract_function_name(code):
        # Extract the function name from the code using regex
        match = re.search(r'def (\w+)\s*\(', code)
        if match:
            return match.group(1)
        raise ValueError("Function name could not be extracted from the code.")

def remove_json_prefix(input_str):
    # Check if the input string starts with "json\n"
    if input_str.startswith("json\n"):
        # Remove the prefix and return the remaining string
        return input_str[len("json\n"):]
    return input_str


class ExecutorStaticAgent:
    def __init__(self,entry):
        self.entry = entry


    def execute_static_analysis(self,code):
        temp_script_path = None
        result = None

        try:
            # Create a temporary file for the script
            with tempfile.NamedTemporaryFile(delete=False, suffix=".py", dir="./tmp") as temp_script:
                temp_script.write(code.encode('utf-8'))
                temp_script_path = temp_script.name

            # Execute bandit on the temporary script
            result = subprocess.run(
                ['bandit', '-r', temp_script_path, '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=6
            )
        except subprocess.TimeoutExpired:
            return FResult.TIMED_OUT, "function timeout"
        except FileNotFoundError:
            # bandit 可执行文件不存在，直接返回错误信息，避免 AttributeError
            return FResult.ERROR, "bandit command not found. Please ensure bandit is installed and in PATH."
        except Exception as e:
            # 其他异常，返回通用错误
            return FResult.ERROR, f"static analysis failed: {e}"
        finally:
            # Clean up the temporary file if it was created
            if temp_script_path and os.path.exists(temp_script_path):
                os.remove(temp_script_path)

        # 下面根据 bandit 的返回码解析结果
        if result is None:
            return FResult.ERROR, "none type"
        if result.returncode == 0:
            return FResult.SAFE, "0", ""
        if result.returncode == 1:
            try:
                bandit_result = json.loads(result.stdout)
                print(bandit_result)
                issues = bandit_result.get("results", [])
                if not issues:
                    return FResult.ERROR, "Unknown CWE", result.stdout
                first_issue = issues[0]
                cwe = first_issue.get("issue_cwe") or {}
                cwe_code = cwe.get("id")
                issue_text = first_issue.get("issue_text")
                if cwe_code is not None:
                    cwe_code = f"CWE-{cwe_code}"
                return FResult.ERROR, cwe_code, issue_text
            except Exception as e:
                return FResult.ERROR, f"failed to parse bandit output: {e}"
        # 其他非 0/1 返回码
        return FResult.ERROR, result.stderr

    def execute_static_analysis_gpt(self,code):

        response = call_chatgpt_analyze_static_security(code)
        if ('no vulnerabilities detected'.lower() in response.lower()):
            return FResult.SAFE, "No CWE"
        else:
            return FResult.ERROR, response

    