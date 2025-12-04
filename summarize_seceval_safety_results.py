import json
from pathlib import Path

RESULT_PATH = Path("results/seceval_safety_agents_demo.json")


def main() -> None:
    if not RESULT_PATH.exists():
        print("Result file not found:", RESULT_PATH)
        return

    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    if not data:
        print("No data in result file.")
        return

    n = len(data)

    # 初始阶段整体统计
    init_unsafe = sum(1 for x in data if not x["initial_bandit_safe"])
    init_test_pass = sum(1 for x in data if x["initial_test_pass"])
    init_fuzz_pass = sum(1 for x in data if x["initial_fuzz_pass"])

    # LLM 基于 Problem 生成的初始实现整体表现（只统计真实存在的样本）
    llm_available = [x for x in data if x.get("llm_initial_bandit_safe") is not None]
    t = len(llm_available)
    if t:
        llm_bandit_safe = sum(1 for x in llm_available if x["llm_initial_bandit_safe"])
        llm_test_pass = sum(1 for x in llm_available if x["llm_initial_test_pass"])
        llm_fuzz_pass = sum(1 for x in llm_available if x["llm_initial_fuzz_pass"])

        # LLM 初始实现修复后的整体表现
        llm_fixed_available = [x for x in llm_available if x.get("llm_fixed_bandit_safe") is not None]
        u = len(llm_fixed_available)
        if u:
            llm_fixed_bandit_safe = sum(1 for x in llm_fixed_available if x["llm_fixed_bandit_safe"])
            llm_fixed_test_pass = sum(1 for x in llm_fixed_available if x["llm_fixed_test_pass"])
            llm_fixed_fuzz_pass = sum(1 for x in llm_fixed_available if x["llm_fixed_fuzz_pass"])

    # 修复后整体统计（只统计实际有修复结果的样本）
    fixed_available = [x for x in data if x["fixed_bandit_safe"] is not None]
    k = len(fixed_available)
    fixed_safe_all = sum(1 for x in fixed_available if x["fixed_bandit_safe"])
    fixed_test_pass_all = sum(1 for x in fixed_available if x["fixed_test_pass"])
    fixed_fuzz_pass_all = sum(1 for x in fixed_available if x["fixed_fuzz_pass"])

    # 修复后（只对最初不安全且有修复结果的样本）
    fixed_candidates = [
        x for x in data
        if not x["initial_bandit_safe"] and x["fixed_bandit_safe"] is not None
    ]
    m = len(fixed_candidates)
    fixed_safe = sum(1 for x in fixed_candidates if x["fixed_bandit_safe"])
    fixed_test_pass = sum(1 for x in fixed_candidates if x["fixed_test_pass"])
    fixed_fuzz_pass = sum(1 for x in fixed_candidates if x["fixed_fuzz_pass"])

    # Secure Code 对照组
    secure_bandit_safe = sum(1 for x in data if x["secure_code_bandit_safe"])
    secure_test_pass = sum(1 for x in data if x["secure_code_test_pass"])

    print("=== SecEval Safety Agents Summary (Demo) ===")
    print(f"Total samples: {n}")

    print("\n-- Initial (Insecure Code) --")
    print(f"Bandit unsafe: {init_unsafe} ({init_unsafe / n:.2%})")
    print(f"Official Test pass: {init_test_pass} ({init_test_pass / n:.2%})")
    print(f"Fuzz pass: {init_fuzz_pass} ({init_fuzz_pass / n:.2%})")

    if t:
        print("\n-- LLM Initial Implementation (from Problem) --")
        print(f"Samples with LLM init: {t}")
        print(f"Bandit safe: {llm_bandit_safe} ({llm_bandit_safe / t:.2%})")
        print(f"Official Test pass: {llm_test_pass} ({llm_test_pass / t:.2%})")
        print(f"Fuzz pass: {llm_fuzz_pass} ({llm_fuzz_pass / t:.2%})")

        if u:
            print("\n-- LLM Fixed Implementation --")
            print(f"Samples with LLM fix: {u}")
            print(f"Bandit safe: {llm_fixed_bandit_safe} ({llm_fixed_bandit_safe / u:.2%})")
            print(f"Official Test pass: {llm_fixed_test_pass} ({llm_fixed_test_pass / u:.2%})")
            print(f"Fuzz pass: {llm_fixed_fuzz_pass} ({llm_fixed_fuzz_pass / u:.2%})")

    if k:
        print("\n-- After Fix (All with fix) --")
        print(f"Samples with fix: {k}")
        print(f"Bandit safe: {fixed_safe_all} ({fixed_safe_all / k:.2%})")
        print(f"Official Test pass: {fixed_test_pass_all} ({fixed_test_pass_all / k:.2%})")
        print(f"Fuzz pass: {fixed_fuzz_pass_all} ({fixed_fuzz_pass_all / k:.2%})")

    if m:
        print("\n-- Among Initially Unsafe & Fixed --")
        print(f"Initially unsafe & fixed: {m}")
        print(f"Bandit safe after fix: {fixed_safe} ({fixed_safe / m:.2%})")
        print(f"Official Test pass after fix: {fixed_test_pass} ({fixed_test_pass / m:.2%})")
        print(f"Fuzz pass after fix: {fixed_fuzz_pass} ({fixed_fuzz_pass / m:.2%})")
    else:
        print("\nNo initially unsafe samples with fix results.")

    print("\n-- Secure Code (Control) --")
    print(f"Bandit safe: {secure_bandit_safe} ({secure_bandit_safe / n:.2%})")
    print(f"Official Test pass: {secure_test_pass} ({secure_test_pass / n:.2%})")


if __name__ == "__main__":
    main()
