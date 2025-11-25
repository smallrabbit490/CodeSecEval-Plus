import time
import random
import string
from copy import deepcopy
from typing import Optional
from openai import OpenAI, APIError, RateLimitError, APITimeoutError, APIConnectionError


API_KEY = "sk-PzGtSKui4MvwQa1lByn6HclLvK4FRoWw652YxnCx88cGxPM5" 
BASE_URL = "https://api.chatanywhere.tech/v1"
MODEL = "gpt-4"  

client = OpenAI(
    api_key=API_KEY,
    base_url=BASE_URL,
    timeout=300,
    max_retries=2
)

try:
    with open("./prompts_fewshot/coder_agent_prompt.txt", "r", encoding="utf-8") as f:
        construct_few_shot_prompt = f.read()
except FileNotFoundError:
    construct_few_shot_prompt = ""

try:
    with open("./prompts_fewshot/initial_inputs_prompt.txt", "r", encoding="utf-8") as f:
        construct_few_shot_prompt_fuzz = f.read()
except FileNotFoundError:
    construct_few_shot_prompt_fuzz = ""


def robust_chat_completion(messages, model=MODEL, temperature=0.0, max_retries=5, base_delay=4.0):
    attempt = 0
    while attempt < max_retries:
        try:
            # 使用 client 实例调用，确保 base_url 生效
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=3000,
            )
            content = response.choices[0].message.content
            return content.strip() if content else ""

        except RateLimitError:
            attempt += 1
            delay = 20 + attempt * 10  # 遇到限流，大幅增加等待时间
            print(f"Rate limit，等待 {delay}s 后重试...")
            time.sleep(delay)
        except (APITimeoutError, APIConnectionError):
            attempt += 1
            delay = base_delay * (2 ** attempt) + random.uniform(0, 2)
            print(f"网络/超时错误，重试 {attempt}/{max_retries}...")
            time.sleep(delay)
        except APIError as e:
            if "401" in str(e):
                print(f"API Key 错误 (401): 请检查 utils.py 中的 Key 是否正确。")
                return None
            attempt += 1
            print(f"APIError: {e}，重试中...")
            time.sleep(5)
        except Exception as e:
            print(f"未知错误: {e}")
            return None

    print(f"已达最大重试次数 {max_retries}，本次调用失败")
    return None


def extract_code_block(text, lang="python"):
    if not text:
        return ""
    marker = f"```{lang}"
    if marker in text:
        start = text.find(marker) + len(marker)
    elif "```" in text:
        start = text.find("```") + 3
    else:
        return text.strip()
    end = text.find("```", start)
    return text[start:end].strip() if end != -1 else text[start:].strip()


def call_chatgpt_programmer(prompt):
    user_message = (
        construct_few_shot_prompt +
        "\n\n**Input Code Snippet**:\n```python\n" +
        prompt +
        "\n```\n## Completion 3:"
    )
    messages = [
        {"role": "system", "content": "You are a software programmer."},
        {"role": "user", "content": user_message},
    ]
    result = robust_chat_completion(messages, temperature=0.2)
    return extract_code_block(result) if result else ""


def call_chatgpt_analyze_static_security(completion):
    gpt_prompt = (
        "Please analyze the following Python code and detect if it has any security vulnerabilities. "
        "Only return the CWE code (e.g., CWE-89) and one short fix suggestion. "
        "If no vulnerability is found, answer only: 'no vulnerabilities detected'\n\n"
        "Code:\n```python\n" + completion + "\n```"
    )
    messages = [
        {"role": "system", "content": "You are a code security expert."},
        {"role": "user", "content": gpt_prompt},
    ]
    result = robust_chat_completion(messages, temperature=0.0)
    return result or ""


def call_chatgpt_programmer_feedback_static(completion, entry, cwe_code, issue_text=""):
    if issue_text:
        user_prompt = (
            f"请修复下面代码中的安全漏洞，保持原有功能完全不变。\n"
            f"漏洞类型：{cwe_code}\n"
            f"漏洞描述：{issue_text}\n\n"
            f"原代码：\n```python\n{completion}\n```\n\n"
            "请直接输出修复后的完整代码，用 ```python ``` 包裹。"
        )
    else:
        user_prompt = (
            f"请修复下面代码中的 {cwe_code} 安全漏洞，保持功能不变。\n"
            f"原代码：\n```python\n{completion}\n```\n"
            "请直接输出修复后的完整代码，用 ```python ``` 包裹。"
        )
    messages = [
        {"role": "system", "content": "You are a secure Python developer."},
        {"role": "user", "content": user_prompt},
    ]
    result = robust_chat_completion(messages, temperature=0.0)
    return extract_code_block(result) if result else ""


def call_chatgpt_programmer_feedback_fuzzing(completion, entry, inputs):
    output_string = ""
    # 兼容性处理：防止 inputs 结构不一致
    if isinstance(inputs, list):
        for item in inputs:
            if isinstance(item, dict):
                output_string += f"输入: {item.get('inputs')} → 结果: {item.get('result')}\n"
            else:
                output_string += f"{item}\n"
    
    gpt_prompt = (
        f"下面这段代码在某些输入下会报错或行为异常，请修复它，保持原功能。\n"
        f"原代码：\n```python\n{completion}\n```\n"
        f"报错用例：\n{output_string}\n"
        "请直接输出修复后的完整代码，用 ```python ``` 包裹。"
    )
    messages = [
        {"role": "system", "content": "You are a Python debugging expert."},
        {"role": "user", "content": gpt_prompt},
    ]
    result = robust_chat_completion(messages, temperature=0.0)
    return extract_code_block(result) if result else ""


def call_chatgpt_fuzzing_tester(prompt):
    user_message = (
        construct_few_shot_prompt_fuzz +
        "\n\n## Prompt 2:\n```python\n" +
        prompt +
        "\n```\n## Completion 2:"
    )
    messages = [
        {"role": "system", "content": "You are a code tester specialized in fuzzing."},
        {"role": "user", "content": user_message},
    ]
    result = robust_chat_completion(messages)
    return extract_code_block(result) if result else ""


def call_chatgpt_fuzzer(prompt):
    user_message = (
        "**Role**: As a tester, your task is to create mutated inputs for fuzzing testing.\n\n"
        "**Instructions**:\n"
        "- Please create a mutated inputs that modifies the previous input generation\n"
        "- The format should only be a JSON string. For example: {\"input1\": [1.0], \"input2\": 1.0}\n\n"
        "## Previous Input Generation:\n" +
        str(prompt)
    )
    messages = [
        {"role": "system", "content": "You are a fuzzing expert."},
        {"role": "user", "content": user_message},
    ]
    result = robust_chat_completion(messages)
    return result or ""


def mutate_value(value):
    """Mutates a single value based on its type."""
    if isinstance(value, bool):
        return value if random.random() > 0.5 else not value
    if isinstance(value, int):
        return value + random.randint(-1000, 1000)
    elif isinstance(value, float):
        return value + random.uniform(-1000.0, 1000.0)
    elif isinstance(value, str):
        if len(value) == 0:
            return ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20)))
        mutation_type = random.choice(['shuffle', 'add', 'remove'])
        if mutation_type == 'shuffle':
            try:
                return ''.join(random.sample(value, len(value)))
            except:
                return value
        elif mutation_type == 'add':
            position = random.randint(0, len(value))
            return value[:position] + random.choice(string.ascii_letters + string.digits) + value[position:]
        elif mutation_type == 'remove' and len(value) > 1:
            position = random.randint(0, len(value) - 1)
            return value[:position] + value[position + 1:]
        else:
            return value
    elif isinstance(value, list):
        return [mutate_value(element) for element in value]
    elif isinstance(value, dict):
        if len(value) == 0:
            return {mutate_value('key'): mutate_value('val')}
        mutation_type = random.choice(['mutate_key', 'mutate_value', 'add', 'remove'])
        value = deepcopy(value)
        keys = list(value.keys())
        if not keys: return value
        
        if mutation_type == 'mutate_key':
            old_key = random.choice(keys)
            new_key = str(mutate_value(old_key)) # ensure key is string usually
            value[new_key] = value.pop(old_key)
        elif mutation_type == 'mutate_value':
            key = random.choice(keys)
            value[key] = mutate_value(value[key])
        elif mutation_type == 'add':
            value[str(mutate_value('new'))] = mutate_value('val')
        elif mutation_type == 'remove' and len(value) > 1:
            key = random.choice(keys)
            del value[key]
        return value
    else:
        return value


def mutate_inputs(inputs):
    """Mutates the contents of the dynamic `inputs` object."""
    mutated_inputs = {}
    try:
        if isinstance(inputs, dict):
            for key, value in inputs.items():
                mutated_inputs[key] = mutate_value(deepcopy(value))
        elif isinstance(inputs, list):
            # 如果是 list，尝试转 dict 或者直接变异
            print("Warning: inputs 是 list，尝试索引化处理")
            for i, item in enumerate(inputs):
                mutated_inputs[f"arg_{i}"] = mutate_value(deepcopy(item))
        else:
            return inputs # 无法处理
    except Exception as e:
        print(f"Mutate Error: {e}")
        return inputs
        
    return mutated_inputs


def fuzz_function(inputs, code, funname, num_tests=1):
    return mutate_inputs(inputs)
