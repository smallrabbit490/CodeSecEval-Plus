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
OUTPUT_PATH = Path("results/secure_code_failure_analysis.txt")


def analyze_secure_code_failures():
    """分析 Secure Code 未通过静态分析或官方测试的原因"""
    
    if RESULT_PATH is None:
        print("❌ 未找到任何结果文件（匹配模式: results/seceval_safety_agents_*.json）")
        return
    
    if not RESULT_PATH.exists():
        print(f"❌ 结果文件不存在: {RESULT_PATH}")
        return
    
    print(f"📊 正在分析结果文件: {RESULT_PATH}\n")
    
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    if not data:
        print("❌ 结果文件为空")
        return
    
    # 筛选出有 Secure Code 测试结果的样本
    samples_with_secure = [x for x in data if x.get("secure_code_bandit_safe") is not None]
    
    if not samples_with_secure:
        print("❌ 没有找到 Secure Code 的测试结果")
        return
    
    # 找出未通过的样本
    bandit_failed = [x for x in samples_with_secure if not x.get("secure_code_bandit_safe")]
    test_failed = [x for x in samples_with_secure if not x.get("secure_code_test_pass")]
    
    # 同时统计 Insecure Code 和 Secure Code 的对比
    both_bandit_failed = [x for x in bandit_failed if not x.get("initial_bandit_safe")]
    both_test_failed = [x for x in test_failed if not x.get("initial_test_pass")]
    
    # 生成报告
    report_lines = []
    report_lines.append("=" * 100)
    report_lines.append("  Secure Code 测试失败原因分析报告")
    report_lines.append("=" * 100)
    report_lines.append(f"  生成时间: 2025年12月18日")
    report_lines.append(f"  总样本数: {len(data)}")
    report_lines.append(f"  有 Secure Code 的样本: {len(samples_with_secure)}")
    report_lines.append("=" * 100)
    
    # ========================================================================
    # 静态分析失败分析
    # ========================================================================
    report_lines.append(f"\n{'='*100}")
    report_lines.append(f"  【1】静态分析（Bandit）失败分析")
    report_lines.append(f"{'='*100}")
    report_lines.append(f"  失败样本数: {len(bandit_failed)}/{len(samples_with_secure)} ({len(bandit_failed)/len(samples_with_secure)*100:.1f}%)")
    
    if bandit_failed:
        report_lines.append(f"  其中 Insecure Code 也失败: {len(both_bandit_failed)} 个")
        report_lines.append(f"\n  详细列表:")
        report_lines.append(f"  {'-'*96}")
        
        for idx, sample in enumerate(bandit_failed, 1):
            report_lines.append(f"\n  [{idx}] ID: {sample['ID']}")
            report_lines.append(f"      入口函数: {sample['entry_point']}")
            report_lines.append(f"      Insecure Code Bandit结果: {'❌ 不安全' if not sample.get('initial_bandit_safe') else '✅ 安全'}")
            report_lines.append(f"      Secure Code Bandit结果: ❌ 不安全")
            
            # 尝试从 initial_cwe 和 initial_issue 获取可能的漏洞信息
            if sample.get('initial_cwe'):
                report_lines.append(f"      检测到的CWE: {sample['initial_cwe']}")
            if sample.get('initial_issue'):
                issue = sample['initial_issue']
                if len(issue) > 200:
                    issue = issue[:200] + "..."
                report_lines.append(f"      问题描述: {issue}")
            
            # 如果有 Secure Code 的完整代码，可以显示（但JSON中可能没有）
            report_lines.append(f"      分析: Secure Code 仍被 Bandit 标记为不安全，可能存在假阳性或修复不完整")
    else:
        report_lines.append(f"  ✅ 所有 Secure Code 均通过静态分析")
    
    # ========================================================================
    # 官方测试失败分析
    # ========================================================================
    report_lines.append(f"\n\n{'='*100}")
    report_lines.append(f"  【2】官方测试失败分析")
    report_lines.append(f"{'='*100}")
    report_lines.append(f"  失败样本数: {len(test_failed)}/{len(samples_with_secure)} ({len(test_failed)/len(samples_with_secure)*100:.1f}%)")
    
    if test_failed:
        report_lines.append(f"  其中 Insecure Code 也失败: {len(both_test_failed)} 个")
        report_lines.append(f"\n  详细列表:")
        report_lines.append(f"  {'-'*96}")
        
        for idx, sample in enumerate(test_failed, 1):
            report_lines.append(f"\n  [{idx}] ID: {sample['ID']}")
            report_lines.append(f"      入口函数: {sample['entry_point']}")
            report_lines.append(f"      Insecure Code 测试结果: {'❌ 失败' if not sample.get('initial_test_pass') else '✅ 通过'}")
            report_lines.append(f"      Secure Code 测试结果: ❌ 失败")
            
            # 显示 Insecure Code 的测试错误（如果有）
            if not sample.get('initial_test_pass') and sample.get('initial_test_info'):
                test_info = sample['initial_test_info']
                if len(test_info) > 300:
                    test_info = test_info[:300] + "..."
                report_lines.append(f"      Insecure Code 错误: {test_info}")
            
            report_lines.append(f"      分析: Secure Code 未能通过官方测试用例，可能存在功能性问题")
            
            # 如果有问题描述，也显示出来
            if sample.get('Problem'):
                problem = sample['Problem']
                if len(problem) > 200:
                    problem = problem[:200] + "..."
                report_lines.append(f"      问题描述: {problem}")
    else:
        report_lines.append(f"  ✅ 所有 Secure Code 均通过官方测试")
    
    # ========================================================================
    # 综合分析
    # ========================================================================
    report_lines.append(f"\n\n{'='*100}")
    report_lines.append(f"  【3】综合分析")
    report_lines.append(f"{'='*100}")
    
    # 两项都失败的样本
    both_failed = [x for x in samples_with_secure 
                   if not x.get("secure_code_bandit_safe") and not x.get("secure_code_test_pass")]
    
    # 两项都通过的样本
    both_passed = [x for x in samples_with_secure 
                   if x.get("secure_code_bandit_safe") and x.get("secure_code_test_pass")]
    
    # 只有一项失败的样本
    only_bandit_failed = [x for x in samples_with_secure 
                          if not x.get("secure_code_bandit_safe") and x.get("secure_code_test_pass")]
    only_test_failed = [x for x in samples_with_secure 
                        if x.get("secure_code_bandit_safe") and not x.get("secure_code_test_pass")]
    
    report_lines.append(f"\n  Secure Code 测试结果分布:")
    report_lines.append(f"    两项全通过:       {len(both_passed)}/{len(samples_with_secure)} ({len(both_passed)/len(samples_with_secure)*100:.1f}%)")
    report_lines.append(f"    两项都失败:       {len(both_failed)}/{len(samples_with_secure)} ({len(both_failed)/len(samples_with_secure)*100:.1f}%)")
    report_lines.append(f"    仅 Bandit 失败:   {len(only_bandit_failed)}/{len(samples_with_secure)} ({len(only_bandit_failed)/len(samples_with_secure)*100:.1f}%)")
    report_lines.append(f"    仅官方测试失败:   {len(only_test_failed)}/{len(samples_with_secure)} ({len(only_test_failed)/len(samples_with_secure)*100:.1f}%)")
    
    # 与 Insecure Code 的对比
    report_lines.append(f"\n  与 Insecure Code 对比:")
    
    # 计算改进情况
    insecure_bandit_pass = sum(1 for x in samples_with_secure if x.get("initial_bandit_safe"))
    secure_bandit_pass = sum(1 for x in samples_with_secure if x.get("secure_code_bandit_safe"))
    insecure_test_pass = sum(1 for x in samples_with_secure if x.get("initial_test_pass"))
    secure_test_pass = sum(1 for x in samples_with_secure if x.get("secure_code_test_pass"))
    
    report_lines.append(f"    Bandit 通过: Insecure {insecure_bandit_pass} → Secure {secure_bandit_pass} (变化 {secure_bandit_pass - insecure_bandit_pass:+d})")
    report_lines.append(f"    测试通过:    Insecure {insecure_test_pass} → Secure {secure_test_pass} (变化 {secure_test_pass - insecure_test_pass:+d})")
    
    # ========================================================================
    # 结论与建议
    # ========================================================================
    report_lines.append(f"\n\n{'='*100}")
    report_lines.append(f"  【4】结论与建议")
    report_lines.append(f"{'='*100}")
    
    if len(bandit_failed) > 0:
        report_lines.append(f"\n  ⚠️  发现 {len(bandit_failed)} 个 Secure Code 未通过 Bandit 静态分析:")
        report_lines.append(f"      可能原因:")
        report_lines.append(f"      1. Bandit 误报（假阳性）")
        report_lines.append(f"      2. Secure Code 的修复不够彻底")
        report_lines.append(f"      3. Bandit 规则配置过于严格")
        report_lines.append(f"      建议: 人工审查这些样本，判断是否为真实漏洞")
    
    if len(test_failed) > 0:
        report_lines.append(f"\n  ⚠️  发现 {len(test_failed)} 个 Secure Code 未通过官方测试:")
        report_lines.append(f"      可能原因:")
        report_lines.append(f"      1. Secure Code 存在功能性错误")
        report_lines.append(f"      2. 官方测试用例设计不合理")
        report_lines.append(f"      3. Secure Code 与测试用例期望不匹配")
        report_lines.append(f"      建议: 检查测试用例和 Secure Code 的具体实现")
    
    if len(bandit_failed) == 0 and len(test_failed) == 0:
        report_lines.append(f"\n  ✅ 所有 Secure Code 均通过静态分析和官方测试")
        report_lines.append(f"     数据集质量良好，可作为可靠的安全代码基准")
    
    report_lines.append(f"\n{'='*100}")
    report_lines.append(f"  报告结束")
    report_lines.append(f"{'='*100}\n")
    
    # 写入文件
    report_text = "\n".join(report_lines)
    OUTPUT_PATH.write_text(report_text, encoding="utf-8")
    
    # 同时打印到控制台
    print(report_text)
    print(f"\n📊 详细报告已保存至: {OUTPUT_PATH}")
    
    return {
        "total_samples": len(samples_with_secure),
        "bandit_failed": len(bandit_failed),
        "test_failed": len(test_failed),
        "both_passed": len(both_passed),
    }


if __name__ == "__main__":
    analyze_secure_code_failures()
