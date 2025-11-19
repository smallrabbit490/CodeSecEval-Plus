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

    # 初始阶段
    init_unsafe = sum(1 for x in data if not x["initial_bandit_safe"])
    init_test_pass = sum(1 for x in data if x["initial_test_pass"])

    # 修复后（只对最初不安全且有修复结果的样本）
    fixed_candidates = [
        x for x in data
        if not x["initial_bandit_safe"] and x["fixed_bandit_safe"] is not None
    ]
    m = len(fixed_candidates)
    fixed_safe = sum(1 for x in fixed_candidates if x["fixed_bandit_safe"])
    fixed_test_pass = sum(1 for x in fixed_candidates if x["fixed_test_pass"])

    print("=== SecEval Safety Agents Summary ===")
    print(f"Total samples: {n}")
    print(f"Initial unsafe by Bandit: {init_unsafe} ({init_unsafe / n:.2%})")
    print(f"Initial pass official Test: {init_test_pass} ({init_test_pass / n:.2%})")
    if m:
        print(f"\nAmong initially unsafe samples with a fix attempt: {m}")
        print(f"Fixed Bandit-safe: {fixed_safe} ({fixed_safe / m:.2%})")
        print(f"Fixed pass official Test: {fixed_test_pass} ({fixed_test_pass / m:.2%})")
    else:
        print("\nNo initially unsafe samples with fix results.")


if __name__ == "__main__":
    main()
