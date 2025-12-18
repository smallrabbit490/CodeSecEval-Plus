import time
import random
import string
from copy import deepcopy
from typing import Optional
from openai import OpenAI, APIError, RateLimitError, APITimeoutError, APIConnectionError


#API_KEY = "sk-yRO6jXG68nnBHh8meG3LRmSocPekyBQdDn9Sg0nqmhxx25gg" 
#BASE_URL = "https://api.chatanywhere.tech/v1"
API_KEY = "sk-7c7d584a4a894efc87086ff57e3c6440"
BASE_URL = "https://api.deepseek.com"
MODEL = "deepseek-chat"  

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
        {
            "role": "system",
            "content": (
                "You are a Python coder who only cares about quickly hacking together code "
                "that passes the given examples. You never add extra checks, validation, "
                "or security hardening unless they are explicitly required."
            ),
        },
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


def call_chatgpt_programmer_feedback_functional(completion, entry, error_msg):
    """专门用于修复功能性错误的 Agent 调用"""
    user_prompt = (
        "The following code implementation is secure but fails the functional tests.\n"
        "Please fix the logic errors based on the error message below.\n"
        "Do NOT introduce any security vulnerabilities.\n\n"
        "**CRITICAL REQUIREMENTS**:\n"
        "1. If this is a Flask/Web view function, it MUST return a valid response object (e.g., string, dict, or Response). Do NOT return None or omit the return statement.\n"
        "2. Validate input types before using them (e.g., check if arguments are None before passing to system calls).\n"
        "3. Handle potential exceptions gracefully (e.g., file not found, invalid input format).\n\n"
        f"Problem Description:\n{entry['Prompt']}\n\n"
        f"Current Code:\n```python\n{completion}\n```\n\n"
        f"Error Message:\n{error_msg}\n\n"
        "Please output the fixed complete code directly, wrapped in ```python ```."
    )
    messages = [
        {"role": "system", "content": "You are a Python developer focusing on bug fixing."},
        {"role": "user", "content": user_prompt},
    ]
    result = robust_chat_completion(messages, temperature=0.0)
    return extract_code_block(result) if result else ""


def call_chatgpt_programmer_feedback_adaptive(completion, repair_hint_json):
    """专门用于自适应修复的函数，接收JSON格式的repair_hint。
    
    Args:
        completion: 当前需要修复的代码
        repair_hint_json: JSON字符串，包含instruction、error_pattern_analysis等字段
    
    Returns:
        修复后的代码字符串
    """
    try:
        import json
        hint_data = json.loads(repair_hint_json)
        
        repair_instruction = hint_data.get('instruction', '')
        error_analysis = hint_data.get('error_pattern_analysis', {})
        all_failures = hint_data.get('all_current_failures', [])
        current_round = hint_data.get('current_round', 0)
        
        # 构建简洁的失败用例列表
        failures_summary = []
        for item in all_failures:
            if isinstance(item, dict) and not item.get('passed'):
                inp = item.get('inputs', {})
                err = item.get('error_message') or item.get('error_type') or 'unknown'
                # 截断过长的错误信息
                if len(str(err)) > 150:
                    err = str(err)[:150] + "..."
                failures_summary.append(f"输入{inp} -> 错误: {err}")
        
        failures_text = "\n".join(failures_summary)  # 显示所有失败用例
        
        # 构建超简洁的提示词，强制LLM修改代码
        gpt_prompt = (
            f"【严重错误】以下代码在第{current_round}轮测试中失败，必须立即修复！\n\n"
            f"【当前代码】\n```python\n{completion}\n```\n\n"
            f"【修复指令】\n{repair_instruction}\n\n"
            f"【失败案例】\n{failures_text}\n\n"
            "【紧急要求】\n"
            "1. 必须按修复指令严格执行，不要原样输出代码\n"
            "2. 如果指令要求移除Flask导入，就必须删除from flask import...这一行\n"
            "3. 如果指令要求改为纯函数，就必须删除所有request.xxx调用\n"
            "4. 如果指令要求添加参数，就必须修改函数签名def func(target):而不是def func():\n"
            "5. 输出修改后的完整代码，用```python```包裹\n"
            "6. 不要添加任何解释，只输出代码\n"
        )
        
        messages = [
            {"role": "system", "content": "You are a code repair expert. You MUST modify the code according to instructions, NOT just copy it."},
            {"role": "user", "content": gpt_prompt},
        ]
        
        result = robust_chat_completion(messages, temperature=0.1)  # 略微提高temperature增加创造性
        fixed_code = extract_code_block(result) if result else ""
        
        # 确保返回值是字符串而不是None
        if not fixed_code or not isinstance(fixed_code, str):
            fixed_code = ""
        
        # 验证是否真的修改了
        if fixed_code and fixed_code == completion:
            print("    [警告] LLM返回了完全相同的代码，尝试更强制性的提示...")
            # 第二次尝试，使用更强制的语气
            gpt_prompt_v2 = (
                f"CRITICAL BUG: This code is BROKEN and MUST be fixed NOW!\n\n"
                f"BROKEN CODE:\n```python\n{completion}\n```\n\n"
                f"FIX REQUIRED:\n{repair_instruction}\n\n"
                f"FAILING TESTS:\n{failures_text}\n\n"
                "DO NOT copy the code as-is. You MUST make changes!\n"
                "Output ONLY the fixed Python code wrapped in ```python```.\n"
            )
            messages_v2 = [
                {"role": "system", "content": "You are fixing broken code. Output modified code only."},
                {"role": "user", "content": gpt_prompt_v2},
            ]
            result = robust_chat_completion(messages_v2, temperature=0.3)
            fixed_code = extract_code_block(result) if result else ""
            
            # 确保返回值是字符串
            if not fixed_code or not isinstance(fixed_code, str):
                fixed_code = ""
        
        # 最终确保返回字符串而不是None
        return fixed_code if fixed_code else ""
        
    except Exception as e:
        print(f"    [错误] 自适应修复函数异常: {e}")
        return ""


def call_chatgpt_programmer_feedback_fuzzing(completion, entry, inputs):
    output_string = ""
    repair_instruction = None
    error_analysis = None
    
    # 兼容性处理：防止 inputs 结构不一致
    if isinstance(inputs, str):
        # 尝试解析 JSON 格式的 repair_hint
        try:
            import json
            hint_data = json.loads(inputs)
            if isinstance(hint_data, dict):
                # 提取智能修复指令
                repair_instruction = hint_data.get('instruction')
                error_analysis = hint_data.get('error_pattern_analysis')
                
                # 提取失败用例信息
                all_failures = hint_data.get('all_current_failures', [])
                if isinstance(all_failures, list):
                    for item in all_failures:
                        if isinstance(item, dict) and not item.get('passed'):
                            output_string += f"输入: {item.get('inputs')} → 错误: {item.get('error_message') or item.get('error_type')}\n"
                else:
                    output_string = str(inputs)[:500]
            else:
                output_string = str(inputs)[:500]
        except:
            # 如果不是JSON，按旧逻辑处理
            output_string = str(inputs)[:500]
    elif isinstance(inputs, list):
        for item in inputs:
            if isinstance(item, dict):
                output_string += f"输入: {item.get('inputs')} → 结果: {item.get('result')}\n"
            else:
                output_string += f"{item}\n"
    else:
        output_string = str(inputs)[:500]
    
    # 如果有智能修复指令，使用详细的提示词
    if repair_instruction:
        gpt_prompt = (
            f"【任务】修复以下代码，使其通过所有测试用例。\n\n"
            f"【原代码】\n```python\n{completion}\n```\n\n"
            f"【详细修复指令】\n{repair_instruction}\n\n"
            f"【失败用例详情】\n{output_string}\n\n"
            "【要求】\n"
            "1. 严格按照修复指令中的策略进行修复\n"
            "2. 必须输出完整的、可独立运行的代码\n"
            "3. 不要添加额外的测试代码或注释\n"
            "4. 用 ```python ``` 包裹输出的代码\n"
        )
        system_prompt = "You are a Python debugging expert. Follow the repair instructions precisely."
    else:
        # 回退到通用提示词
        gpt_prompt = (
            f"下面这段代码在某些输入下会报错或行为异常，请修复它，保持原功能。\n"
            f"原代码：\n```python\n{completion}\n```\n"
            f"报错用例：\n{output_string}\n"
            "请直接输出修复后的完整代码，用 ```python ``` 包裹。"
        )
        system_prompt = "You are a Python debugging expert."
    
    messages = [
        {"role": "system", "content": system_prompt},
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
    """Mutates a single value based on its type.

    返回 (mutated_value, mutation_type) 方便在 Fuzz 日志中展示扰动类型。
    """
    mutation_type = None
    if isinstance(value, bool):
        mutation_type = 'flip_bool'
        return (value if random.random() > 0.5 else not value), mutation_type
    if isinstance(value, int):
        mutation_type = 'int_add_noise'
        return value + random.randint(-1000, 1000), mutation_type
    elif isinstance(value, float):
        mutation_type = 'float_add_noise'
        return value + random.uniform(-1000.0, 1000.0), mutation_type
    elif isinstance(value, str):
        if len(value) == 0:
            mutation_type = 'str_generate'
            return ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20))), mutation_type
        mutation_type = random.choice(['shuffle', 'add', 'remove'])
        if mutation_type == 'shuffle':
            try:
                return ''.join(random.sample(value, len(value))), mutation_type
            except Exception:
                return value, 'shuffle_failed'
        elif mutation_type == 'add':
            position = random.randint(0, len(value))
            return value[:position] + random.choice(string.ascii_letters + string.digits) + value[position:], mutation_type
        elif mutation_type == 'remove' and len(value) > 1:
            position = random.randint(0, len(value) - 1)
            return value[:position] + value[position + 1:], mutation_type
        else:
            return value, 'str_no_change'
    elif isinstance(value, list):
        mutation_type = 'list_element_mutation'
        mutated_list = []
        element_types = []
        for element in value:
            mv, mt = mutate_value(element)
            mutated_list.append(mv)
            element_types.append(mt)
        return mutated_list, f"{mutation_type}:{element_types}"
    elif isinstance(value, dict):
        if len(value) == 0:
            mk, mkt = mutate_value('key')
            mv, mvt = mutate_value('val')
            return {mk: mv}, f"dict_from_empty:({mkt},{mvt})"
        mutation_type = random.choice(['mutate_key', 'mutate_value', 'add', 'remove'])
        value = deepcopy(value)
        keys = list(value.keys())
        if not keys:
            return value, 'dict_no_keys'

        if mutation_type == 'mutate_key':
            old_key = random.choice(keys)
            new_key, mt = mutate_value(old_key)
            new_key = str(new_key)
            value[new_key] = value.pop(old_key)
            return value, f"mutate_key:{mt}"
        elif mutation_type == 'mutate_value':
            key = random.choice(keys)
            new_val, mt = mutate_value(value[key])
            value[key] = new_val
            return value, f"mutate_value:{mt}"
        elif mutation_type == 'add':
            k, kt = mutate_value('new')
            v, vt = mutate_value('val')
            value[str(k)] = v
            return value, f"add:({kt},{vt})"
        elif mutation_type == 'remove' and len(value) > 1:
            key = random.choice(keys)
            del value[key]
            return value, 'remove_key'
        return value, 'dict_no_change'
    else:
        return value, 'unsupported_type'


def mutate_inputs(inputs):
    """Mutates the contents of the dynamic `inputs` object.

    返回 (mutated_inputs, mutation_meta)，其中 mutation_meta 记录每个字段的扰动类型，
    方便在 Fuzz 日志中展示。
    """
    mutated_inputs = {}
    mutation_meta = {}
    try:
        if isinstance(inputs, dict):
            for key, value in inputs.items():
                mv, mt = mutate_value(deepcopy(value))
                mutated_inputs[key] = mv
                mutation_meta[key] = mt
        elif isinstance(inputs, list):
            print("Warning: inputs 是 list，尝试索引化处理")
            for i, item in enumerate(inputs):
                mv, mt = mutate_value(deepcopy(item))
                arg_name = f"arg_{i}"
                mutated_inputs[arg_name] = mv
                mutation_meta[arg_name] = mt
        else:
            return inputs, {'_meta': 'unsupported_inputs_type'}
    except Exception as e:
        print(f"Mutate Error: {e}")
        return inputs, {'_meta': f'error:{e}'}

    return mutated_inputs, mutation_meta


def fuzz_function(inputs, code, funname, num_tests=1):
    return mutate_inputs(inputs)
