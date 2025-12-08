import argparse
import json

from eval_seceval_safety_agents import (
    DATA_PATH,
    EXPLANATION_PATH,
    OFFICIAL_TEST_TIMEOUT,
    FUZZ_TEST_TIMEOUT,
    evaluate_sample,
)


def load_dataset():
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    try:
        explanations = json.loads(EXPLANATION_PATH.read_text(encoding="utf-8"))
        id_to_explanation = {
            item["ID"]: item.get("Insecure Code Explanation", "")
            for item in explanations
        }
        for item in data:
            if item["ID"] in id_to_explanation:
                item["Insecure Code Explanation"] = id_to_explanation[item["ID"]]
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Warning: Could not load explanations: {exc}")
    return data


def run_single(id_value: str, test_timeout: int, fuzz_timeout: int):
    data = load_dataset()
    target = None
    for item in data:
        if item["ID"] == id_value:
            target = item
            break
    if not target:
        print(f"Sample with ID={id_value} not found.")
        return

    print(f"\n=== Evaluating {target['ID']} ({target['Entry_Point']}) ===")
    print(
        f"Using official-test timeout={test_timeout}s, "
        f"fuzz timeout={fuzz_timeout}s",
    )
    res = evaluate_sample(
        target,
        test_timeout=test_timeout,
        fuzz_timeout=fuzz_timeout,
    )

    print("\n--- Summary ---")
    print("Initial: bandit_safe=", res["initial_bandit_safe"],
          "test_pass=", res["initial_test_pass"],
          "fuzz_pass=", res["initial_fuzz_pass"])
    print("Fixed:   bandit_safe=", res["fixed_bandit_safe"],
          "test_pass=", res["fixed_test_pass"],
          "fuzz_pass=", res["fixed_fuzz_pass"])
    print("LLM Initial: bandit_safe=", res["llm_initial_bandit_safe"],
          "test_pass=", res["llm_initial_test_pass"],
          "fuzz_pass=", res["llm_initial_fuzz_pass"])
    print("LLM Fixed:   bandit_safe=", res["llm_fixed_bandit_safe"],
          "test_pass=", res["llm_fixed_test_pass"],
          "fuzz_pass=", res["llm_fixed_fuzz_pass"])


def parse_args():
    parser = argparse.ArgumentParser(description="Run a single SecEval sample")
    parser.add_argument(
        "--id",
        default="CWE-835_author_1",
        help="Sample ID from SecEvalBase.json",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=OFFICIAL_TEST_TIMEOUT,
        help="Timeout (seconds) for each official test run",
    )
    parser.add_argument(
        "--fuzz-timeout",
        dest="fuzz_timeout",
        type=int,
        default=FUZZ_TEST_TIMEOUT,
        help="Timeout (seconds) for each fuzzing run",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_single(args.id, args.timeout, args.fuzz_timeout)