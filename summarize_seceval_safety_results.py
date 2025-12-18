import json
from pathlib import Path
import glob
import os


def get_latest_result_file():
    """自动查找 results 目录下最新的 seceval_safety_agents_*.json 文件"""
    results_dir = Path("results")
    if not results_dir.exists():
        return None
    
    # 查找所有匹配的结果文件
    pattern = str(results_dir / "seceval_safety_agents_*.json")
    files = glob.glob(pattern)
    
    if not files:
        return None
    
    # 按修改时间排序，返回最新的文件
    latest_file = max(files, key=os.path.getmtime)
    return Path(latest_file)


RESULT_PATH = get_latest_result_file()


def print_stage_summary(title: str, stage_data: dict, total_samples: int):
    """打印单个阶段的统计汇总"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")
    
    if not stage_data:
        print("  无数据")
        return
    
    available = stage_data.get('available', 0)
    if available == 0:
        print("  无有效样本")
        return
    
    print(f"  有效样本数: {available}/{total_samples} ({available/total_samples:.1%})")
    
    # 初始状态
    if 'initial' in stage_data:
        init = stage_data['initial']
        print(f"\n  【初始状态】")
        print(f"    静态分析安全: {init['bandit_safe']}/{available} ({init['bandit_safe']/available:.1%})")
        print(f"    官方测试通过: {init['test_pass']}/{available} ({init['test_pass']/available:.1%})")
        print(f"    Fuzz测试通过: {init['fuzz_pass']}/{available} ({init['fuzz_pass']/available:.1%})")
        
        # 计算全部通过的样本数
        all_pass = init.get('all_pass', 0)
        if all_pass is not None:
            print(f"    三项全通过:   {all_pass}/{available} ({all_pass/available:.1%})")
    
    # 修复后状态
    if 'fixed' in stage_data:
        fixed = stage_data['fixed']
        fixed_count = fixed['count']
        if fixed_count > 0:
            print(f"\n  【修复后状态】")
            print(f"    触发修复的样本: {fixed_count}/{available} ({fixed_count/available:.1%})")
            print(f"    静态分析安全: {fixed['bandit_safe']}/{fixed_count} ({fixed['bandit_safe']/fixed_count:.1%})")
            print(f"    官方测试通过: {fixed['test_pass']}/{fixed_count} ({fixed['test_pass']/fixed_count:.1%})")
            print(f"    Fuzz测试通过: {fixed['fuzz_pass']}/{fixed_count} ({fixed['fuzz_pass']/fixed_count:.1%})")
            
            # 计算修复后全部通过的样本数
            all_pass = fixed.get('all_pass', 0)
            if all_pass is not None:
                print(f"    三项全通过:   {all_pass}/{fixed_count} ({all_pass/fixed_count:.1%})")
            
            # 计算提升幅度
            if 'initial' in stage_data:
                init_all_pass_rate = stage_data['initial'].get('all_pass', 0) / available * 100
                fixed_all_pass_rate = all_pass / fixed_count * 100 if fixed_count > 0 else 0
                improvement = fixed_all_pass_rate - init_all_pass_rate
                print(f"\n  【修复效果】")
                print(f"    全通过率提升: {init_all_pass_rate:.1f}% → {fixed_all_pass_rate:.1f}% (提升 {improvement:+.1f}%)")
        else:
            print(f"\n  【修复后状态】")
            print(f"    未触发修复流程（代码已满足要求）")


def main() -> None:
    if RESULT_PATH is None:
        print("❌ 未找到任何结果文件（匹配模式: results/seceval_safety_agents_*.json）")
        return
    
    if not RESULT_PATH.exists():
        print(f"❌ 结果文件不存在: {RESULT_PATH}")
        return

    print(f"📊 正在分析结果文件: {RESULT_PATH}")
    print(f"   文件修改时间: {Path(RESULT_PATH).stat().st_mtime}\n")
    
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    if not data:
        print("❌ 结果文件为空")
        return

    n = len(data)
    
    print("="*80)
    print("  SecEval Safety Agents 三阶段评估汇总报告")
    print("="*80)
    print(f"  评估样本总数: {n}")
    print(f"  评估时间: 2025年12月18日")
    print("="*80)

    # ========================================================================
    # [A] 数据集不安全代码阶段 (Insecure Code)
    # ========================================================================
    stage_a = {
        'available': n,
        'initial': {
            'bandit_safe': sum(1 for x in data if x.get("initial_bandit_safe")),
            'test_pass': sum(1 for x in data if x.get("initial_test_pass")),
            'fuzz_pass': sum(1 for x in data if x.get("initial_fuzz_pass")),
        }
    }
    # 计算初始阶段三项全通过
    stage_a['initial']['all_pass'] = sum(
        1 for x in data 
        if x.get("initial_bandit_safe") and x.get("initial_test_pass") and x.get("initial_fuzz_pass")
    )
    
    # 修复后统计
    fixed_samples = [x for x in data if x.get("fixed_bandit_safe") is not None]
    stage_a['fixed'] = {
        'count': len(fixed_samples),
        'bandit_safe': sum(1 for x in fixed_samples if x.get("fixed_bandit_safe")),
        'test_pass': sum(1 for x in fixed_samples if x.get("fixed_test_pass")),
        'fuzz_pass': sum(1 for x in fixed_samples if x.get("fixed_fuzz_pass")),
    }
    # 计算修复后三项全通过
    stage_a['fixed']['all_pass'] = sum(
        1 for x in fixed_samples 
        if x.get("fixed_bandit_safe") and x.get("fixed_test_pass") and x.get("fixed_fuzz_pass")
    )
    
    print_stage_summary("[A] 数据集不安全代码 (Insecure Code)", stage_a, n)

    # ========================================================================
    # [B] LLM生成代码阶段 (基于Problem描述)
    # ========================================================================
    llm_samples = [x for x in data if x.get("llm_initial_bandit_safe") is not None]
    llm_count = len(llm_samples)
    
    if llm_count > 0:
        stage_b = {
            'available': llm_count,
            'initial': {
                'bandit_safe': sum(1 for x in llm_samples if x.get("llm_initial_bandit_safe")),
                'test_pass': sum(1 for x in llm_samples if x.get("llm_initial_test_pass")),
                'fuzz_pass': sum(1 for x in llm_samples if x.get("llm_initial_fuzz_pass")),
            }
        }
        # 计算LLM初始三项全通过
        stage_b['initial']['all_pass'] = sum(
            1 for x in llm_samples 
            if x.get("llm_initial_bandit_safe") and x.get("llm_initial_test_pass") and x.get("llm_initial_fuzz_pass")
        )
        
        # LLM修复后统计
        llm_fixed_samples = [x for x in llm_samples if x.get("llm_fixed_bandit_safe") is not None]
        stage_b['fixed'] = {
            'count': len(llm_fixed_samples),
            'bandit_safe': sum(1 for x in llm_fixed_samples if x.get("llm_fixed_bandit_safe")),
            'test_pass': sum(1 for x in llm_fixed_samples if x.get("llm_fixed_test_pass")),
            'fuzz_pass': sum(1 for x in llm_fixed_samples if x.get("llm_fixed_fuzz_pass")),
        }
        # 计算LLM修复后三项全通过
        stage_b['fixed']['all_pass'] = sum(
            1 for x in llm_fixed_samples 
            if x.get("llm_fixed_bandit_safe") and x.get("llm_fixed_test_pass") and x.get("llm_fixed_fuzz_pass")
        )
        
        print_stage_summary("[B] LLM生成代码 (基于Problem描述)", stage_b, n)
    else:
        print(f"\n{'='*80}")
        print(f"  [B] LLM生成代码 (基于Problem描述)")
        print(f"{'='*80}")
        print("  无数据")

    # ========================================================================
    # [C] 自适应测试 + 多轮修复阶段
    # ========================================================================
    adaptive_samples = [x for x in data if x.get("adaptive_test_repair") and isinstance(x["adaptive_test_repair"], dict)]
    adaptive_count = len(adaptive_samples)
    
    if adaptive_count > 0:
        print(f"\n{'='*80}")
        print(f"  [C] 自适应测试 + 多轮修复 (Adaptive Test & Repair)")
        print(f"{'='*80}")
        print(f"  有效样本数: {adaptive_count}/{n} ({adaptive_count/n:.1%})")
        
        # 统计自适应测试的状态分布
        finished = sum(1 for x in adaptive_samples if x["adaptive_test_repair"].get("status") == "finished")
        test_gen_failed = sum(1 for x in adaptive_samples if x["adaptive_test_repair"].get("status") == "test_generation_failed")
        exception = sum(1 for x in adaptive_samples if x["adaptive_test_repair"].get("status") == "exception")
        other = adaptive_count - finished - test_gen_failed - exception
        
        print(f"\n  【执行状态】")
        print(f"    成功完成:     {finished}/{adaptive_count} ({finished/adaptive_count:.1%})")
        print(f"    测试生成失败: {test_gen_failed}/{adaptive_count} ({test_gen_failed/adaptive_count:.1%})")
        print(f"    执行异常:     {exception}/{adaptive_count} ({exception/adaptive_count:.1%})")
        if other > 0:
            print(f"    其他状态:     {other}/{adaptive_count} ({other/adaptive_count:.1%})")
        
        # 对成功完成的样本进行深度分析
        finished_samples = [x for x in adaptive_samples if x["adaptive_test_repair"].get("status") == "finished"]
        if finished_samples:
            print(f"\n  【成功完成的样本详细分析】 (共 {len(finished_samples)} 个)")
            
            # 不安全代码的自适应修复效果
            insecure_converged = 0
            insecure_improved = 0
            insecure_total_rounds = 0
            insecure_convergence_rounds = []
            
            # LLM代码的自适应修复效果
            llm_converged = 0
            llm_improved = 0
            llm_total_rounds = 0
            llm_convergence_rounds = []
            
            for sample in finished_samples:
                rounds = sample["adaptive_test_repair"].get("rounds", [])
                if not rounds:
                    continue
                
                insecure_total_rounds += len(rounds)
                llm_total_rounds += len(rounds)
                
                # 分析不安全代码
                first_round = rounds[0]
                last_round = rounds[-1]
                
                if not first_round.get("insecure", {}).get("skipped"):
                    ins_first = first_round.get("insecure", {}).get("detail", [])
                    ins_last = last_round.get("insecure", {}).get("detail", [])
                    
                    if isinstance(ins_first, list) and isinstance(ins_last, list) and len(ins_first) > 0:
                        first_pass = sum(1 for c in ins_first if c.get("passed"))
                        last_pass = sum(1 for c in ins_last if c.get("passed"))
                        
                        # 检查是否收敛（全部通过）
                        if last_pass == len(ins_last):
                            insecure_converged += 1
                            # 找到第一次全部通过的轮次
                            for idx, r in enumerate(rounds, 1):
                                if (r.get("insecure") or {}).get("all_pass"):
                                    insecure_convergence_rounds.append(idx)
                                    break
                        
                        # 检查是否有改进
                        if last_pass > first_pass:
                            insecure_improved += 1
                
                # 分析LLM代码
                if not first_round.get("llm", {}).get("skipped"):
                    llm_first = first_round.get("llm", {}).get("detail", [])
                    llm_last = last_round.get("llm", {}).get("detail", [])
                    
                    if isinstance(llm_first, list) and isinstance(llm_last, list) and len(llm_first) > 0:
                        first_pass = sum(1 for c in llm_first if c.get("passed"))
                        last_pass = sum(1 for c in llm_last if c.get("passed"))
                        
                        # 检查是否收敛
                        if last_pass == len(llm_last):
                            llm_converged += 1
                            # 找到第一次全部通过的轮次
                            for idx, r in enumerate(rounds, 1):
                                if (r.get("llm") or {}).get("all_pass"):
                                    llm_convergence_rounds.append(idx)
                                    break
                        
                        # 检查是否有改进
                        if last_pass > first_pass:
                            llm_improved += 1
            
            # 打印不安全代码的自适应修复统计
            print(f"\n    → 不安全代码自适应修复:")
            print(f"      完全收敛（全部通过）: {insecure_converged}/{len(finished_samples)} ({insecure_converged/len(finished_samples):.1%})")
            print(f"      有所改进（通过率↑）: {insecure_improved}/{len(finished_samples)} ({insecure_improved/len(finished_samples):.1%})")
            if insecure_convergence_rounds:
                avg_rounds = sum(insecure_convergence_rounds) / len(insecure_convergence_rounds)
                print(f"      平均收敛轮次: {avg_rounds:.1f} 轮")
                print(f"      收敛轮次分布: min={min(insecure_convergence_rounds)}, max={max(insecure_convergence_rounds)}, median={sorted(insecure_convergence_rounds)[len(insecure_convergence_rounds)//2]}")
            
            # 打印LLM代码的自适应修复统计
            print(f"\n    → LLM代码自适应修复:")
            print(f"      完全收敛（全部通过）: {llm_converged}/{len(finished_samples)} ({llm_converged/len(finished_samples):.1%})")
            print(f"      有所改进（通过率↑）: {llm_improved}/{len(finished_samples)} ({llm_improved/len(finished_samples):.1%})")
            if llm_convergence_rounds:
                avg_rounds = sum(llm_convergence_rounds) / len(llm_convergence_rounds)
                print(f"      平均收敛轮次: {avg_rounds:.1f} 轮")
                print(f"      收敛轮次分布: min={min(llm_convergence_rounds)}, max={max(llm_convergence_rounds)}, median={sorted(llm_convergence_rounds)[len(llm_convergence_rounds)//2]}")
    else:
        print(f"\n{'='*80}")
        print(f"  [C] 自适应测试 + 多轮修复")
        print(f"{'='*80}")
        print("  无数据或已禁用")

    # ========================================================================
    # 对照组：Secure Code
    # ========================================================================
    secure_samples = [x for x in data if x.get("secure_code_bandit_safe") is not None]
    if secure_samples:
        print(f"\n{'='*80}")
        print(f"  【对照组】Secure Code（数据集提供的安全代码）")
        print(f"{'='*80}")
        secure_count = len(secure_samples)
        secure_bandit = sum(1 for x in secure_samples if x.get("secure_code_bandit_safe"))
        secure_test = sum(1 for x in secure_samples if x.get("secure_code_test_pass"))
        
        print(f"  有效样本数: {secure_count}/{n} ({secure_count/n:.1%})")
        print(f"  静态分析安全: {secure_bandit}/{secure_count} ({secure_bandit/secure_count:.1%})")
        print(f"  官方测试通过: {secure_test}/{secure_count} ({secure_test/secure_count:.1%})")
        print(f"  两项全通过:   {sum(1 for x in secure_samples if x.get('secure_code_bandit_safe') and x.get('secure_code_test_pass'))}/{secure_count} ({sum(1 for x in secure_samples if x.get('secure_code_bandit_safe') and x.get('secure_code_test_pass'))/secure_count:.1%})")

    print(f"\n{'='*80}")
    print("  报告生成完毕")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
