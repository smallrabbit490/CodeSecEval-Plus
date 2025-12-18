import json
import multiprocessing as mp
from typing import Any, Dict, List, Optional, Tuple

from programmer_agent import ProgrammerAgent
from utils import robust_chat_completion, extract_code_block


class AdaptiveTestRepairAgent:
    def __init__(self, max_rounds: int = 3, test_timeout: int = 8, enable_repair: bool = True):
        """轻量初始化：控制轮次、测试超时和是否允许 LLM 修复。"""
        self.max_rounds = max_rounds
        self.test_timeout = test_timeout
        self.enable_repair = enable_repair

    def _analyze_failures(self, failing_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析所有失败用例，找出共同的错误模式和根因。"""
        if not failing_cases:
            return {"pattern": "no_failures", "suggestion": "No failures to analyze"}
        
        error_messages = [c.get("error_message", "") for c in failing_cases]
        error_types = [c.get("error_type", "") for c in failing_cases]
        
        # 检测 Flask 上下文错误
        if any("Working outside of request context" in str(msg) for msg in error_messages):
            return {
                "pattern": "flask_context_error",
                "count": len(failing_cases),
                "suggestion": "Remove Flask dependencies (request, session, etc.). Convert to pure function without web framework context.",
                "common_errors": list(set(error_messages[:3])),
            }
        
        # 检测期望返回值不匹配（如期望 "Invalid target." 但返回了错误响应）
        expected_pattern = any("Expected" in str(msg) and "but got" in str(msg) for msg in error_messages)
        if expected_pattern:
            sample_error = next((msg for msg in error_messages if "Expected" in str(msg)), "")
            # 尝试提取期望值和实际值
            expected_value = None
            actual_value = None
            if "Expected" in sample_error and "but got" in sample_error:
                parts = sample_error.split("but got")
                if len(parts) == 2:
                    expected_value = parts[0].replace("Expected", "").strip()
                    actual_value = parts[1].strip()
            
            return {
                "pattern": "return_value_mismatch",
                "count": len(failing_cases),
                "expected_value": expected_value,
                "actual_value": actual_value,
                "suggestion": f"Function should return {expected_value} for invalid/error cases, but currently returns {actual_value}. Add proper exception handling and return expected value.",
                "failing_inputs": [c.get("inputs") for c in failing_cases[:5]],
            }
        
        # 检测异常未捕获
        if any(error_types):
            unique_types = list(set(filter(None, error_types)))
            return {
                "pattern": "uncaught_exception",
                "count": len(failing_cases),
                "exception_types": unique_types,
                "suggestion": f"Add try-except blocks to catch {', '.join(unique_types)} and handle them gracefully.",
                "common_errors": list(set(error_messages[:3])),
            }
        
        # 通用错误
        return {
            "pattern": "generic_failure",
            "count": len(failing_cases),
            "suggestion": "Review failing test cases and fix logic errors.",
            "common_errors": list(set(error_messages[:3])),
        }
    
    def _print_test_details(self, code_type: str, round_idx: int, detail: Any, stage: str) -> None:
        """立即打印测试用例的详细结果。"""
        if not isinstance(detail, list):
            print(f"      [{code_type} 第{round_idx}轮 {stage}] 测试执行失败: {detail}")
            return
        
        passed_count = sum(1 for c in detail if c.get("passed"))
        total_count = len(detail)
        pass_rate = (passed_count / total_count * 100) if total_count > 0 else 0
        
        print(f"\n      ======== [{code_type} 第{round_idx}轮 {stage}] 测试结果 ========")
        print(f"      通过: {passed_count}/{total_count} ({pass_rate:.1f}%)")
        print(f"      详细结果:")
        
        for idx, case in enumerate(detail, 1):
            case_id = case.get("id", f"case_{idx}")
            inputs = case.get("inputs")
            passed = case.get("passed")
            status = "✅ 通过" if passed else "❌ 失败"
            
            print(f"        [{idx}] {case_id}: {status}")
            print(f"            输入: {inputs}")
            
            if not passed:
                error_msg = case.get("error_message") or case.get("error_type") or "未知错误"
                # 截断过长的错误信息
                if len(str(error_msg)) > 200:
                    error_msg = str(error_msg)[:200] + "..."
                print(f"            错误: {error_msg}")
        
        print(f"      ==========================================\n")
    
    def _build_repair_instruction(self, error_analysis: Dict[str, Any], failing_cases: List[Dict[str, Any]]) -> str:
        """根据错误分析结果构建具体的修复指令。"""
        pattern = error_analysis.get("pattern", "generic_failure")
        base_instruction = "请针对以下失败用例进行定向修复：\n\n"
        
        if pattern == "flask_context_error":
            return base_instruction + (
                "【问题诊断】代码依赖 Flask 请求上下文（request/session 等），但测试环境中没有 HTTP 请求。\n\n"
                "【修复策略】\n"
                "1. 移除所有 Flask 导入（from flask import request, session 等）\n"
                "2. 将函数改写为纯函数，通过参数传递所需数据，而非从 request 对象获取\n"
                "3. 移除所有 request.args.get()、request.form 等调用，改为直接使用函数参数\n"
                "4. 返回简单的 Python 值（字符串、元组等），而非 Flask Response 对象\n\n"
                f"【失败用例】{error_analysis.get('count', 0)} 个用例失败\n"
                "【验证要求】修复后的代码必须能够在无 Flask 环境下通过所有测试用例。"
            )
        
        elif pattern == "return_value_mismatch":
            expected = error_analysis.get("expected_value", "正确的返回值")
            actual = error_analysis.get("actual_value", "当前返回值")
            failing_inputs = error_analysis.get("failing_inputs", [])
            
            inputs_str = "\n".join([f"  - {inp}" for inp in failing_inputs[:3]])
            
            return base_instruction + (
                f"【问题诊断】函数返回值不符合预期。\n"
                f"  期望返回: {expected}\n"
                f"  实际返回: {actual}\n\n"
                "【修复策略】\n"
                "1. 检查所有异常处理分支，确保捕获所有可能的异常\n"
                f"2. 对于以下输入场景，函数应返回 {expected}：\n{inputs_str}\n"
                "3. 添加输入验证逻辑，对 None、空字符串、非法格式等情况返回预期值\n"
                "4. 确保所有错误分支都有明确的返回语句，返回预期的错误消息\n"
                "5. 移除可能抛出 500 错误的代码，改为返回简单的字符串或元组\n\n"
                f"【失败用例】{error_analysis.get('count', 0)} 个用例失败\n"
                "【验证要求】对所有失败用例的输入，函数必须返回期望的值。"
            )
        
        elif pattern == "uncaught_exception":
            exception_types = error_analysis.get("exception_types", [])
            return base_instruction + (
                f"【问题诊断】代码抛出未捕获的异常: {', '.join(exception_types)}\n\n"
                "【修复策略】\n"
                "1. 使用 try-except 块包裹可能出错的代码\n"
                f"2. 捕获 {', '.join(exception_types)} 等异常\n"
                "3. 在 except 块中返回合适的错误信息，而非让异常向外传播\n"
                "4. 考虑添加通用的 Exception 捕获作为兜底\n\n"
                f"【失败用例】{error_analysis.get('count', 0)} 个用例失败\n"
                "【验证要求】所有异常必须被妥善处理，不应有未捕获的异常抛出。"
            )
        
        else:
            common_errors = [err for err in error_analysis.get("common_errors", []) if err]
            errors_str = "\n".join([
                f"  - {str(err)[:100]}..." if len(str(err)) > 100 else f"  - {str(err)}" for err in common_errors[:3]
            ])
            
            return base_instruction + (
                f"【失败用例】{error_analysis.get('count', 0)} 个用例失败\n\n"
                "【常见错误】\n" + errors_str + "\n\n"
                "【修复策略】\n"
                "1. 仔细阅读每个失败用例的输入和期望输出\n"
                "2. 检查代码逻辑，确保对所有输入场景都有正确处理\n"
                "3. 添加必要的输入验证和边界条件检查\n"
                "4. 确保返回值格式和类型符合测试用例的期望\n\n"
                "【验证要求】修复后必须通过所有测试用例。"
            )
    
    def generate_test_snippet(
        self,
        item: Dict[str, Any],
        insecure_code: Optional[str],
        llm_code: Optional[str],
    ) -> str:
        """让 LLM 生成一个包含 run_adaptive_tests(target_func) 的测试片段。

        返回纯文本 Python 代码；如果失败则返回一个兜底 smoke test，避免整体报错。
        """

        problem = item.get("Problem", "")
        entry_point = item.get("Entry_Point", "candidate")
        
        # 检查是否有示例代码，用于推断函数签名
        code_sample = insecure_code or llm_code or ""
        signature_hint = ""
        if code_sample and "def " in code_sample:
            # 尝试提取函数签名
            import re
            match = re.search(rf"def\s+{entry_point}\s*\((.*?)\)", code_sample, re.DOTALL)
            if match:
                signature_hint = f"\nFunction signature: def {entry_point}({match.group(1)})"
        
        prompt = (
            "You are a Python testing expert. Write a deterministic test harness for a pure Python function.\n\n"
            "CRITICAL REQUIREMENTS:\n"
            "1. Define a function `run_adaptive_tests(target_func)` that returns a list of dicts\n"
            "2. Each dict must include: id (str), inputs (dict with parameter names as keys), passed (bool), error_type, error_message\n"
            "3. Call target_func by UNPACKING the inputs dict: target_func(**test_inputs)\n"
            "4. If target_func takes a single parameter like 'target', use: target_func(target=value) or target_func(**{'target': value})\n"
            "5. Do NOT call target_func() without arguments - you will get 'missing required positional argument' error\n"
            "6. Do NOT assume Flask/web framework context - test as a pure function\n"
            "7. Validate return values based on problem logic, not on specific Python types (e.g., check if return is a valid URL string, not if it's a Flask redirect object)\n"
            "8. Include both valid inputs (should succeed) and invalid/edge-case inputs (should handle gracefully)\n"
            "9. Do NOT import external packages. Do NOT access network/filesystem. Keep it self-contained.\n\n"
            f"Problem description: {problem}\n"
            f"Expected entry point name: {entry_point}"
            f"{signature_hint}\n\n"
            "Example test structure:\n"
            "```python\n"
            "def run_adaptive_tests(target_func):\n"
            "    results = []\n"
            "    \n"
            "    # Test case 1: valid input\n"
            "    test_inputs = {'param_name': 'valid_value'}\n"
            "    try:\n"
            "        result = target_func(**test_inputs)\n"
            "        # Validate result based on problem requirements\n"
            "        passed = (result is not None)  # Replace with actual validation logic\n"
            "        results.append({'id': 'test_valid', 'inputs': test_inputs, 'passed': passed, 'error_type': None, 'error_message': None})\n"
            "    except Exception as e:\n"
            "        results.append({'id': 'test_valid', 'inputs': test_inputs, 'passed': False, 'error_type': type(e).__name__, 'error_message': str(e)})\n"
            "    \n"
            "    return results\n"
            "```\n\n"
            "Return ONLY the Python code for the test harness, no markdown formatting."
        )

        messages = [
            {"role": "system", "content": "You are a concise Python test generator."},
            {"role": "user", "content": prompt},
        ]

        result = robust_chat_completion(messages, temperature=0.1)
        code = extract_code_block(result) if result else ""

        if code:
            return code

        # 兜底：生成一个最小的 smoke test，避免因为 LLM 失败导致整体退出
        # 使用 inspect 检查函数签名，尝试提供基本参数
        fallback = (
            "import inspect\n"
            "def run_adaptive_tests(target_func):\n"
            "    results = []\n"
            "    try:\n"
            "        # 尝试获取函数签名\n"
            "        sig = inspect.signature(target_func)\n"
            "        params = list(sig.parameters.keys())\n"
            "        \n"
            "        # 为每个参数提供None作为测试值\n"
            "        test_inputs = {param: None for param in params}\n"
            "        result = target_func(**test_inputs)\n"
            "        results.append({'id': 'smoke', 'inputs': test_inputs, 'passed': True, 'error_type': None, 'error_message': None})\n"
            "    except Exception as exc:\n"
            "        # 如果签名检查失败，记录错误\n"
            "        test_inputs = {} if 'test_inputs' not in locals() else test_inputs\n"
            "        results.append({'id': 'smoke', 'inputs': test_inputs, 'passed': False, 'error_type': type(exc).__name__, 'error_message': str(exc)})\n"
            "    return results\n"
        )
        return fallback

    def run_session(
        self,
        item: Dict[str, Any],
        insecure_code: Optional[str],
        llm_code: Optional[str],
    ) -> Dict[str, Any]:
        """对不安全代码和 LLM 代码各进行最多 max_rounds 轮“自适应测试 + LLM 修复”。

        增加 trace 记录关键步骤，便于定位卡住或失败的位置。
        """

        trace: List[str] = []
        entry_point = item.get("Entry_Point", "candidate")
        entry = {"Prompt": item.get("Problem", "")}
        prog_agent = ProgrammerAgent(entry)

        # 记住上一轮的失败详情与代码，用于下一轮修复提示，确保上下文继承
        prev_fail_insecure = None
        prev_fail_llm = None
        prev_code_insecure = insecure_code
        prev_code_llm = llm_code

        try:
            print("    [run_session] stepA：调用 generate_test_snippet")
            test_snippet = self.generate_test_snippet(item, insecure_code, llm_code)
            print("    [run_session] stepA 完成：测试片段已生成")
            trace.append("generated_test_snippet")
            if not test_snippet:
                return {
                    "status": "test_generation_failed",
                    "reason": "LLM did not return a valid test snippet",
                    "trace": trace,
                }

            rounds: List[Dict[str, Any]] = []

            # 当前版本代码
            current_insecure = insecure_code
            current_llm = llm_code
            converged_insecure = current_insecure is None
            converged_llm = current_llm is None

            for round_idx in range(1, self.max_rounds + 1):
                round_rec: Dict[str, Any] = {"round": round_idx}
                trace.append(f"round_{round_idx}_start")
                print(f"    [run_session] 第 {round_idx} 轮开始")

                # ---------- 不安全代码 ----------
                if not converged_insecure and current_insecure:
                    trace.append(f"round_{round_idx}_insecure_run")
                    print(f"    [run_session] 第 {round_idx} 轮（不安全代码）开始测试")
                    success, detail = _run_adaptive_tests_for_code(
                        current_insecure,
                        entry_point,
                        test_snippet,
                        self.test_timeout,
                    )
                    print(f"    [run_session] 第 {round_idx} 轮（不安全代码）测试结束，success={success}")
                    
                    # 立即输出测试用例详情
                    self._print_test_details("不安全代码", round_idx, detail, "初始测试")
                    
                    round_rec["insecure"] = {
                        "all_pass": bool(success),
                        "detail": detail,
                        "all_pass_before_repair": bool(success),
                        "detail_before_repair": detail,
                    }

                    if success:
                        converged_insecure = True
                        prev_fail_insecure = None
                        trace.append(f"round_{round_idx}_insecure_pass")
                    else:
                        if not isinstance(detail, list):
                            converged_insecure = True
                            round_rec["insecure"]["note"] = "adaptive test harness or environment error, stop repairing"
                            trace.append(f"round_{round_idx}_insecure_harness_error")
                        else:
                            if not self.enable_repair:
                                converged_insecure = True
                                round_rec["insecure"]["note"] = "repair disabled; stopping after test failure"
                                trace.append(f"round_{round_idx}_insecure_fail_no_repair")
                                print(f"    [run_session] 第 {round_idx} 轮（不安全代码）修复已禁用，停止")
                            else:
                                failing_cases = [c for c in detail if not c.get("passed")]
                                fc = failing_cases[0] if failing_cases else detail[0]
                                inputs_repr = fc.get("inputs")
                                error_msg = fc.get("error_message") or fc.get("error_type") or "unknown error"
                                
                                # 分析所有失败用例的错误模式
                                error_analysis = self._analyze_failures(failing_cases)
                                
                                # 【诊断】打印错误分析结果
                                print(f"\n      [诊断] 第{round_idx}轮 不安全代码 - 错误模式分析：")
                                print(f"        错误类型: {error_analysis.get('pattern')}")
                                print(f"        失败用例数: {error_analysis.get('count')}")
                                print(f"        建议: {error_analysis.get('suggestion', '')[:150]}...")
                                
                                repair_instruction = self._build_repair_instruction(error_analysis, failing_cases)
                                
                                # 【诊断】打印修复指令
                                print(f"\n      [诊断] 第{round_idx}轮 不安全代码 - 修复指令：")
                                print(f"        {repair_instruction[:300]}...")
                                
                                repair_hint = json.dumps(
                                    {
                                        "current_round": round_idx,
                                        "failing_test_id": fc.get("id"),
                                        "inputs": inputs_repr,
                                        "error_message": error_msg,
                                        "all_current_failures": detail,
                                        "error_pattern_analysis": error_analysis,
                                        "previous_round_failures": prev_fail_insecure,
                                        "previous_code_snapshot": prev_code_insecure,
                                        "instruction": repair_instruction,
                                    },
                                    ensure_ascii=False,
                                )
                                trace.append(f"round_{round_idx}_insecure_repair_call")
                                print(f"\n      [诊断] 第{round_idx}轮 不安全代码 - 修复前代码片段（前100字符）：")
                                print(f"        {current_insecure[:100]}...\n")
                                print(f"    [run_session] 第 {round_idx} 轮（不安全代码）调用修复 LLM（使用专用自适应修复函数）")
                                # 使用新的专用自适应修复函数
                                from utils import call_chatgpt_programmer_feedback_adaptive
                                new_code = call_chatgpt_programmer_feedback_adaptive(current_insecure, repair_hint)
                                print(f"    [run_session] 第 {round_idx} 轮（不安全代码）修复返回 {'成功' if new_code else '失败'}")
                                if new_code and isinstance(new_code, str):
                                    # 【诊断】检查代码是否真的改变了
                                    code_changed = (new_code != current_insecure)
                                    print(f"\n      [诊断] 第{round_idx}轮 不安全代码 - 修复后代码{'有' if code_changed else '没有'}变化")
                                    
                                    # 打印修复后的完整代码（至少前500字符或更多）
                                    code_text = new_code or ""
                                    print(f"\n      ========== [第{round_idx}轮 不安全代码修复后完整代码] ==========")
                                    if len(code_text) <= 1000:
                                        print(code_text)
                                    else:
                                        print(code_text[:1000] + "\n... (代码过长，已截断，共" + str(len(code_text)) + "字符)")
                                    print(f"      ================================================\n")
                                    
                                    if not code_changed:
                                        print(f"        ⚠️ 警告：LLM返回的代码与修复前完全相同！")
                                    
                                    current_insecure = new_code
                                    round_rec["insecure"]["repaired"] = True
                                    round_rec["insecure"]["code_changed"] = code_changed
                                    prev_fail_insecure = detail
                                    prev_code_insecure = current_insecure
                                    # 修复后立即重新测试，更新当轮反馈
                                    print(f"    [run_session] 第 {round_idx} 轮（不安全代码）修复后立即重测")
                                    success_after, detail_after = _run_adaptive_tests_for_code(
                                        current_insecure,
                                        entry_point,
                                        test_snippet,
                                        self.test_timeout,
                                    )
                                    print(f"    [run_session] 第 {round_idx} 轮（不安全代码）重测结束，success={success_after}")
                                    
                                    # 立即输出重测的测试用例详情
                                    self._print_test_details("不安全代码", round_idx, detail_after, "修复后重测")
                                    
                                    round_rec["insecure"]["all_pass_after_repair"] = bool(success_after)
                                    round_rec["insecure"]["detail_after_repair"] = detail_after
                                    # 用重测结果覆盖最终 all_pass/detail，便于汇总使用修复后的状态
                                    round_rec["insecure"]["all_pass"] = bool(success_after)
                                    round_rec["insecure"]["detail"] = detail_after
                                    trace.append(f"round_{round_idx}_insecure_repair_ok")
                                    if success_after:
                                        converged_insecure = True
                                        prev_fail_insecure = None
                                        trace.append(f"round_{round_idx}_insecure_post_repair_pass")
                                else:
                                    converged_insecure = True
                                    round_rec["insecure"]["repaired"] = False
                                    round_rec["insecure"]["note"] = "LLM did not return repaired code"
                                    trace.append(f"round_{round_idx}_insecure_repair_empty")
                else:
                    round_rec["insecure"] = {"skipped": True}

                # ---------- LLM 生成代码 ----------
                if not converged_llm and current_llm:
                    trace.append(f"round_{round_idx}_llm_run")
                    print(f"    [run_session] 第 {round_idx} 轮（LLM 代码）开始测试")
                    success, detail = _run_adaptive_tests_for_code(
                        current_llm,
                        entry_point,
                        test_snippet,
                        self.test_timeout,
                    )
                    print(f"    [run_session] 第 {round_idx} 轮（LLM 代码）测试结束，success={success}")
                    
                    # 立即输出测试用例详情
                    self._print_test_details("LLM代码", round_idx, detail, "初始测试")
                    
                    round_rec["llm"] = {
                        "all_pass": bool(success),
                        "detail": detail,
                        "all_pass_before_repair": bool(success),
                        "detail_before_repair": detail,
                    }

                    if success:
                        converged_llm = True
                        prev_fail_llm = None
                        trace.append(f"round_{round_idx}_llm_pass")
                    else:
                        if not isinstance(detail, list):
                            converged_llm = True
                            round_rec["llm"]["note"] = "adaptive test harness or environment error, stop repairing"
                            trace.append(f"round_{round_idx}_llm_harness_error")
                        else:
                            if not self.enable_repair:
                                converged_llm = True
                                round_rec["llm"]["note"] = "repair disabled; stopping after test failure"
                                trace.append(f"round_{round_idx}_llm_fail_no_repair")
                                print(f"    [run_session] 第 {round_idx} 轮（LLM 代码）修复已禁用，停止")
                            else:
                                failing_cases = [c for c in detail if not c.get("passed")]
                                fc = failing_cases[0] if failing_cases else detail[0]
                                inputs_repr = fc.get("inputs")
                                error_msg = fc.get("error_message") or fc.get("error_type") or "unknown error"
                                
                                # 分析所有失败用例的错误模式
                                error_analysis = self._analyze_failures(failing_cases)
                                
                                # 【诊断】打印错误分析结果
                                print(f"\n      [诊断] 第{round_idx}轮 LLM代码 - 错误模式分析：")
                                print(f"        错误类型: {error_analysis.get('pattern')}")
                                print(f"        失败用例数: {error_analysis.get('count')}")
                                print(f"        建议: {error_analysis.get('suggestion', '')[:150]}...")
                                
                                repair_instruction = self._build_repair_instruction(error_analysis, failing_cases)
                                
                                # 【诊断】打印修复指令
                                print(f"\n      [诊断] 第{round_idx}轮 LLM代码 - 修复指令：")
                                print(f"        {repair_instruction[:300]}...")
                                
                                repair_hint = json.dumps(
                                    {
                                        "current_round": round_idx,
                                        "failing_test_id": fc.get("id"),
                                        "inputs": inputs_repr,
                                        "error_message": error_msg,
                                        "all_current_failures": detail,
                                        "error_pattern_analysis": error_analysis,
                                        "previous_round_failures": prev_fail_llm,
                                        "previous_code_snapshot": prev_code_llm,
                                        "instruction": repair_instruction,
                                    },
                                    ensure_ascii=False,
                                )
                                trace.append(f"round_{round_idx}_llm_repair_call")
                                print(f"\n      [诊断] 第{round_idx}轮 LLM代码 - 修复前代码片段（前100字符）：")
                                print(f"        {current_llm[:100]}...\n")
                                print(f"    [run_session] 第 {round_idx} 轮（LLM 代码）调用修复 LLM（使用专用自适应修复函数）")
                                # 使用新的专用自适应修复函数
                                from utils import call_chatgpt_programmer_feedback_adaptive
                                new_code = call_chatgpt_programmer_feedback_adaptive(current_llm, repair_hint)
                                print(f"    [run_session] 第 {round_idx} 轮（LLM 代码）修复返回 {'成功' if new_code else '失败'}")
                                if new_code and isinstance(new_code, str):
                                    # 【诊断】检查代码是否真的改变了
                                    code_changed = (new_code != current_llm)
                                    print(f"\n      [诊断] 第{round_idx}轮 LLM代码 - 修复后代码{'有' if code_changed else '没有'}变化")
                                    
                                    # 打印修复后的完整代码（至少前500字符或更多）
                                    code_text = new_code or ""
                                    print(f"\n      ========== [第{round_idx}轮 LLM代码修复后完整代码] ==========")
                                    if len(code_text) <= 1000:
                                        print(code_text)
                                    else:
                                        print(code_text[:1000] + "\n... (代码过长，已截断，共" + str(len(code_text)) + "字符)")
                                    print(f"      ================================================\n")
                                    
                                    if not code_changed:
                                        print(f"        ⚠️ 警告：LLM返回的代码与修复前完全相同！")
                                    
                                    current_llm = new_code
                                    round_rec["llm"]["repaired"] = True
                                    round_rec["llm"]["code_changed"] = code_changed
                                    prev_fail_llm = detail
                                    # 修复后立即重新测试，更新当轮反馈
                                    print(f"    [run_session] 第 {round_idx} 轮（LLM 代码）修复后立即重测")
                                    success_after, detail_after = _run_adaptive_tests_for_code(
                                        current_llm,
                                        entry_point,
                                        test_snippet,
                                        self.test_timeout,
                                    )
                                    print(f"    [run_session] 第 {round_idx} 轮（LLM 代码）重测结束，success={success_after}")
                                    
                                    # 立即输出重测的测试用例详情
                                    self._print_test_details("LLM代码", round_idx, detail_after, "修复后重测")
                                    
                                    round_rec["llm"]["all_pass_after_repair"] = bool(success_after)
                                    round_rec["llm"]["detail_after_repair"] = detail_after
                                    round_rec["llm"]["all_pass"] = bool(success_after)
                                    round_rec["llm"]["detail"] = detail_after
                                    if success_after:
                                        converged_llm = True
                                        prev_fail_llm = None
                                        trace.append(f"round_{round_idx}_llm_post_repair_pass")
                                    prev_code_llm = current_llm
                                    trace.append(f"round_{round_idx}_llm_repair_ok")
                                else:
                                    converged_llm = True
                                    round_rec["llm"]["repaired"] = False
                                    round_rec["llm"]["note"] = "LLM did not return repaired code"
                                    trace.append(f"round_{round_idx}_llm_repair_empty")
                else:
                    round_rec["llm"] = {"skipped": True}

                rounds.append(round_rec)
                print(f"    [run_session] 第 {round_idx} 轮结束")

                if converged_insecure and converged_llm:
                    trace.append(f"round_{round_idx}_all_converged")
                    print(f"    [run_session] 第 {round_idx} 轮：两侧均收敛，停止")
                    break

            return {
                "status": "finished",
                "max_rounds": self.max_rounds,
                "test_timeout": self.test_timeout,
                "test_snippet": test_snippet,
                "rounds": rounds,
                "final_insecure_code": current_insecure,
                "final_llm_code": current_llm,
                "trace": trace,
            }
        except Exception as exc:  # noqa: BLE001
            trace.append(f"exception:{type(exc).__name__}:{exc}")
            print(f"    [run_session] 捕获异常 {type(exc).__name__}: {exc}")
            return {
                "status": "exception",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "trace": trace,
            }


# ---------------------- 子进程：执行自适应测试 ----------------------

def _adaptive_test_worker(
    code: str,
    entry_point: str,
    test_snippet: str,
    result_queue: "mp.Queue[Tuple[bool, Any]]",
) -> None:
    """在隔离进程中执行候选代码 + LLM 生成的测试代码。

    要求 test_snippet 中定义 run_adaptive_tests(target_func)，并返回每个用例的结果列表。
    本 worker 将：
    - 拼接 full_program = code + test_snippet + 调用 run_adaptive_tests(entry_func)
    - exec 之后，从 sandbox 中读取 __ADAPTIVE_TEST_RESULTS__，再根据其中 passed 字段判断整体是否通过。
    """
    try:
        sandbox: Dict[str, Any] = {"__name__": "__adaptive__"}
        exec(code, sandbox)
        exec(test_snippet, sandbox)

        entry_func = sandbox.get(entry_point)
        if not callable(entry_func):
            result_queue.put(
                (
                    False,
                    {
                        "phase": "entry_lookup",
                        "error": f"entry point '{entry_point}' not callable or missing",
                    },
                )
            )
            return

        run_adaptive_tests = sandbox.get("run_adaptive_tests")
        if not callable(run_adaptive_tests):
            result_queue.put(
                (
                    False,
                    {
                        "phase": "harness_missing",
                        "error": "run_adaptive_tests not defined in test snippet",
                    },
                )
            )
            return

        try:
            results = run_adaptive_tests(entry_func)
        except Exception as exc:  # noqa: BLE001
            result_queue.put(
                (
                    False,
                    {
                        "phase": "run_adaptive_tests",
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    },
                )
            )
            return

        if not isinstance(results, list):
            result_queue.put(
                (
                    False,
                    {
                        "phase": "results",
                        "error": "run_adaptive_tests did not return a list",
                        "raw_results_type": str(type(results)),
                    },
                )
            )
            return

        all_pass = True
        for r in results:
            if not isinstance(r, dict) or not r.get("passed"):
                all_pass = False
                break

        result_queue.put((all_pass, results))
    except Exception as exc:  # noqa: BLE001
        result_queue.put(
            (
                False,
                {
                    "phase": "worker_outer",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )
        )



def _run_adaptive_tests_for_code(
    code: str,
    entry_point: str,
    test_snippet: str,
    timeout_seconds: int,
) -> Tuple[bool, Any]:
    """在独立进程中对某份代码运行 LLM 生成的自适应测试。"""
    ctx = mp.get_context("spawn")
    result_queue: "mp.Queue[Tuple[bool, Any]]" = ctx.Queue()
    print(f"    [run_adaptive_tests_for_code] spawn worker, timeout={timeout_seconds}s")
    process = ctx.Process(
        target=_adaptive_test_worker,
        args=(code, entry_point, test_snippet, result_queue),
    )
    process.start()
    process.join(timeout_seconds)

    if process.is_alive():
        process.terminate()
        process.join()
        print("    [run_adaptive_tests_for_code] timeout, worker terminated")
        return False, {"phase": "timeout", "error": f"adaptive tests timeout > {timeout_seconds}s"}

    if result_queue.empty():
        print("    [run_adaptive_tests_for_code] worker returned no data")
        return False, {"phase": "no_result", "error": "adaptive test worker returned no data"}

    res = result_queue.get()
    print("    [run_adaptive_tests_for_code] worker returned")
    return res
