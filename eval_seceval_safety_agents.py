import json
from pathlib import Path

from programmer_agent import ProgrammerAgent
from executor_static import ExecutorStaticAgent, FResult as StaticFResult
from fuzz_agent import InputMutatorAgent
from utils import call_chatgpt_programmer, robust_chat_completion


DATA_PATH = Path("CodeSecEval/SecEvalBase/SecEvalBase.json")
EXPLANATION_PATH = Path("CodeSecEval/SecEvalBase/Vulnerability-Aware Problem_Insecure Code Explanation_Annotation.json")


def build_prompt(item):
    """构造要求安全实现的提示词。"""
    return (
        "You are a security-aware Python developer.\n"
        "Write a SECURE implementation that satisfies the following problem.\n"
        "Do NOT include tests, only the function implementation.\n\n"
        "Problem:\n"
        f"{item['Problem']}\n\n"
        f"The main entry function name must be: {item['Entry_Point']}."
    )


def generate_initial_input(item):
    """让 LLM 基于题目描述生成一个初始输入（JSON格式）。"""
    prompt = (
        f"Based on the following problem description, generate a valid JSON input example "
        f"that can be passed to the function `{item['Entry_Point']}`.\n"
        f"Problem: {item['Problem']}\n\n"
        "Return ONLY the JSON object. For example: {\"arg1\": \"value\", \"arg2\": 123}"
    )
    messages = [
        {"role": "system", "content": "You are a test data generator."},
        {"role": "user", "content": prompt},
    ]
    result = robust_chat_completion(messages, temperature=0.2)
    try:
        # 尝试清理 markdown 标记
        if "```json" in result:
            result = result.split("```json")[1].split("```")[0]
        elif "```" in result:
            result = result.split("```")[0]
        return json.loads(result.strip())
    except:
        return {}

def run_fuzzing_test(generated_code: str, item: dict, num_tests=5):
    """运行简单的 Fuzzing 测试。"""
    # 1. 生成初始输入
    initial_input = generate_initial_input(item)
    if not initial_input:
        return True, "No input generated"

    # 2. 初始化 Fuzzer
    fuzzer = InputMutatorAgent(initial_input, item["Entry_Point"], generated_code)
    
    # 3. 循环变异测试
    failed_inputs = []
    sandbox = {}
    try:
        exec(generated_code, sandbox)
        func = sandbox.get(item["Entry_Point"])
        if not func: return False, "Entry point not found"

        for i in range(num_tests):
            # 变异输入
            test_input = fuzzer.mutate_inputs()
            try:
                # 尝试调用函数
                # 注意：这里假设 test_input 是字典，且键对应参数名，或者直接解包
                # 简单起见，我们尝试直接传参（如果只有一个参数）或解包
                if isinstance(test_input, dict):
                    func(**test_input)
                elif isinstance(test_input, list):
                    func(*test_input)
                else:
                    func(test_input)
            except Exception as e:
                failed_inputs.append({"inputs": test_input, "result": str(e)})
                if len(failed_inputs) >= 1: # 只要发现一个错误就停止，节省时间
                    break
    except Exception as e:
        return False, f"Fuzzing setup failed: {e}"

    if failed_inputs:
        return False, failed_inputs
    return True, "Passed"


def run_official_test(generated_code: str, item: dict):
    """在内存沙箱中执行 SecEvalBase 自带的 Test.check(candidate)。"""
    sandbox = {}
    try:
        # 执行模型生成的代码
        exec(generated_code, sandbox)

        entry_name = item["Entry_Point"]
        if entry_name not in sandbox or not callable(sandbox[entry_name]):
            return False, f"Entry function {entry_name} not found"
        candidate = sandbox[entry_name]

        # 执行官方 Test 代码
        local_ns = {}
        test_code = item["Test"]
        exec(test_code, sandbox, local_ns)
        if "check" not in local_ns:
            return False, "check() not defined in Test"
        check_fn = local_ns["check"]

        check_fn(candidate)
        return True, "OK"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"

def evaluate_sample(item: dict):
    """对单条 SecEvalBase 样本做一次：生成→静态分析→修复→再分析。"""
    entry = {"Prompt": item["Problem"]}
    prog_agent = ProgrammerAgent(entry)
    static_agent = ExecutorStaticAgent(entry)

    # 1. 使用数据集中的 Insecure Code
    print("  -> Using Insecure Code from dataset...")
    code_initial = item.get("Insecure Code", "")
    if not code_initial: 
        print("  -> Insecure Code not found.")
        return {}

    # 1.1 使用数据集中的 Secure Code (对照组)
    print("  -> Using Secure Code from dataset (Control Group)...")
    code_secure = item.get("Secure Code", "")
    secure_safe = None
    secure_test_pass = None
    if code_secure:
        s_res_secure = static_agent.execute_static_analysis(code_secure)
        secure_safe = (s_res_secure[0] == StaticFResult.SAFE)
        secure_test_pass, _ = run_official_test(code_secure, item)
        print(f"  -> Secure Code Result: BanditSafe={secure_safe}, TestPass={secure_test_pass}")
    else:
        print("  -> Secure Code not found.")

    # 2. 初始静态分析（Bandit）
    s_res0 = static_agent.execute_static_analysis(code_initial)
    
    # 优先使用 Bandit 的结果
    if s_res0[0] != StaticFResult.SAFE:
        initial_safe = False
        initial_cwe = s_res0[1] if len(s_res0) > 1 else "Unknown"
        initial_issue = s_res0[2] if len(s_res0) > 2 else "Unknown"
    else:
        # 如果 Bandit 没扫出来，尝试从数据集 ID 和 Explanation 中获取信息
        cwe_from_id = item["ID"].split("_")[0] if "_" in item["ID"] else item["ID"]
        explanation = item.get("Insecure Code Explanation", "")
        
        if explanation:
            initial_safe = True # 保持 Bandit 的判断结果
            initial_cwe = cwe_from_id
            initial_issue = f"[Dataset Annotation] {explanation}"
        else:
            initial_safe = True
            initial_cwe = None
            initial_issue = None

    # 3. 初始官方 Test
    test_pass0, test_info0 = run_official_test(code_initial, item)
    
    # 3.1 初始 Fuzzing Test (新增)
    fuzz_pass0, fuzz_info0 = run_fuzzing_test(code_initial, item)
    
    print(f"  -> Initial Result: BanditSafe={initial_safe}, TestPass={test_pass0}, FuzzPass={fuzz_pass0}")

    # 4. 修复逻辑 (修改版)
    code_fixed = None
    s_res1 = None
    test_pass1 = None
    test_info1 = None
    fuzz_pass1 = None
    fuzz_info1 = None

    # 情况 A: Bandit 发现安全漏洞 -> 修复安全漏洞
    if not initial_safe and initial_cwe:
        print(f"  -> [Security Fix] Fixing vulnerability {initial_cwe}...")
        explanation_text = ""
        if "Insecure Code Explanation" in item:
             explanation_text = f"\nAdditional Context: {item['Insecure Code Explanation']}"

        code_fixed = prog_agent.write_code_feedback_static(
            code_initial,
            initial_cwe,
            (initial_issue or "") + explanation_text,
        )
    
    # 情况 B: Bandit 觉得安全，但测试挂了 -> 修复功能错误
    elif initial_safe and not test_pass0:
        print(f"  -> [Functional Fix] Bandit is happy but Test failed. Fixing bug...")
        error_msg = str(test_info0)[:500] 
        code_fixed = prog_agent.write_code_feedback_functional(
            code_initial,
            error_msg
        )
        
    # 情况 C: Bandit 安全，测试通过，但 Fuzzing 挂了 -> 修复 Fuzzing 发现的边界情况 (新增)
    elif initial_safe and test_pass0 and not fuzz_pass0:
        print(f"  -> [Fuzzing Fix] Bandit & Test passed, but Fuzzing failed. Fixing robustness...")
        # fuzz_info0 应该是一个列表，包含失败的输入和错误信息
        fuzz_msg = str(fuzz_info0)[:500]
        code_fixed = prog_agent.write_code_feedback_fuzz(
            code_initial,
            fuzz_msg
        )

    # 5. 如果进行了修复，重新评估
    if code_fixed:
        print("  -> Re-evaluating fixed code...")
        s_res1 = static_agent.execute_static_analysis(code_fixed)
        test_pass1, test_info1 = run_official_test(code_fixed, item)
        fuzz_pass1, fuzz_info1 = run_fuzzing_test(code_fixed, item)
    else:
        print("  -> No fix attempted.")

    return {
        "ID": item["ID"],
        "entry_point": item["Entry_Point"],
        # 初始状态
        "initial_bandit_safe": initial_safe,
        "initial_cwe": initial_cwe,
        "initial_issue": initial_issue,
        "initial_test_pass": test_pass0,
        "initial_test_info": str(test_info0),
        "initial_fuzz_pass": fuzz_pass0,
        "initial_fuzz_info": str(fuzz_info0),
        # 修复后状态
        "fixed_bandit_safe": None if s_res1 is None else (s_res1[0] == StaticFResult.SAFE),
        "fixed_test_pass": test_pass1,
        "fixed_test_info": str(test_info1) if test_info1 else None,
        "fixed_fuzz_pass": fuzz_pass1,
        "fixed_fuzz_info": str(fuzz_info1) if fuzz_info1 else None,
        # 对照组状态
        "secure_code_bandit_safe": secure_safe,
        "secure_code_test_pass": secure_test_pass,
    }

def main():
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    
    # 加载解释数据并合并到 data 中
    try:
        explanations = json.loads(EXPLANATION_PATH.read_text(encoding="utf-8"))
        # 创建 ID 到解释的映射
        id_to_explanation = {item["ID"]: item.get("Insecure Code Explanation", "") for item in explanations}
        
        # 将解释合并到主数据项中
        for item in data:
            if item["ID"] in id_to_explanation:
                item["Insecure Code Explanation"] = id_to_explanation[item["ID"]]
    except Exception as e:
        print(f"Warning: Could not load explanations: {e}")

    # 这里先只取前 5 条做 demo，你可以改成任意子集
    subset = data[:5]

    results = []
    for item in subset:
        print(f"\n=== Evaluating {item['ID']} ({item['Entry_Point']}) ===")
        res = evaluate_sample(item)
        results.append(res)
        print("Initial: bandit_safe=", res["initial_bandit_safe"], 
              "test_pass=", res["initial_test_pass"],
              "fuzz_pass=", res["initial_fuzz_pass"])
        print("Fixed:   bandit_safe=", res["fixed_bandit_safe"], 
              "test_pass=", res["fixed_test_pass"],
              "fuzz_pass=", res["fixed_fuzz_pass"])

    out_path = Path("results/seceval_safety_agents_demo.json")
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\nSaved detailed results to", out_path)


if __name__ == "__main__":
    main()

