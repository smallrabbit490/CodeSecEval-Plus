# AutoSafeCoder 扩展说明（SecEval 安全智能体评估）

本文件说明本次在原项目基础上新增的几个脚本/机制，它们主要用于在 `CodeSecEval/SecEvalBase` 数据集上，模拟“安全智能体”式的自动修复与安全评估流程，并总结目前存在的限制与问题。

---

## 一、新增文件及其作用

- `eval_seceval_safety_agents.py`
  - 在 `CodeSecEval/SecEvalBase/SecEvalBase.json` 数据集上运行一个精简版的“安全智能体”评估流程。
  - 对每条样本执行：
    1. 读取题目描述 `Problem` 及入口函数 `Entry_Point`；
    2. 调用项目中的 `ProgrammerAgent`（底层依赖 `utils.py` 的 LLM 封装）生成一份“安全实现”代码；
    3. 使用 `ExecutorStaticAgent`（`executor_static.py`）调用 Bandit 做静态安全分析，提取 CWE 及问题描述；
    4. 利用数据集自带的 `Test` 代码，在沙箱环境中运行 `check(candidate)`，检测功能与显式安全条件是否通过；
    5. 若代码被 Bandit 判定为不安全且存在 CWE 信息，则调用 `write_code_feedback_static` 触发一次“安全智能体式”修复，请 LLM 在静态分析反馈的基础上改写代码；
    6. 对修复后的代码再次进行 Bandit 分析与官方 Test 检测；
    7. 将初始与修复后的安全状态（是否通过 Bandit、是否通过 Test、CWE 编号、错误信息等）汇总为结构化结果并保存到 `results/` 目录。

- `summarize_seceval_safety_results.py`
  - 读取 `eval_seceval_safety_agents.py` 生成的结果 JSON 文件（例如 `results/seceval_safety_agents_demo.json`）。
  - 统计并打印若干高层指标，例如：
    - 样本总数；
    - 初始代码中被 Bandit 判定为不安全的比例；
    - 初始代码通过官方 Test 的比例；
    - 在被判定为不安全的样本中，有尝试修复的数量；
    - 修复后通过 Bandit 检查的比例；
    - 修复后通过官方 Test 的比例。
  - 这些统计可以看作是“安全智能体修复能力”的一个初步量化视角，为后续论文或实验报告提供基础数据。

- `test_chatanywhere_ping.py`
  - 用于独立测试当前环境下通过 chatanywhere 转发 API 调用 LLM 是否连通和可用。
  - 使用 `OpenAI` 官方 SDK，以 `base_url = "https://api.chatanywhere.tech/v1"` + 用户的 API Key 发起一个极简对话请求（如发送 `"ping"`），并设置较短的超时时间（例如 15 秒）。
  - 若该脚本正常返回结果，说明网络连通性和密钥配置基本没有问题，有助于定位项目中更复杂调用场景下的超时原因。

---

## 二、对数据集检测机制的说明

本次扩展主要围绕 `CodeSecEval/SecEvalBase` 数据集，构建了一个“生成 → 检测 → 修复 → 再检测”的安全智能体工作流，核心机制如下：

1. **样本读取与 Prompt 构造**
   - 从 `SecEvalBase.json` 中依次读取若干条样本（当前脚本默认只取前 5 条做 Demo，可根据需要扩展）。
   - 对每条样本，使用其 `Problem` 字段描述任务与安全要求，并结合 `Entry_Point` 指定需要实现的函数名，构造自然语言 Prompt。

2. **安全实现代码生成（ProgrammerAgent）**
   - 调用 `ProgrammerAgent`（内部使用 `utils.py` 中的 `call_chatgpt_programmer`）生成一份“尽量安全”的 Python 实现代码。
   - Prompt 中明确要求：遵守题目描述的功能需求，同时避免常见安全问题，并重点关注对应 CWE 类别（如果有）。

3. **静态安全分析（Bandit）**
   - 将生成的代码写入临时 `.py` 文件，通过 `ExecutorStaticAgent.execute_static_analysis` 调用 Bandit 进行静态分析。
   - 若 Bandit 报告问题，则从 JSON 输出中解析出：
     - CWE 编号（若存在 `issue_cwe.id`）；
     - 具体的 `issue_text` 描述。
   - 静态分析结果用于：
     - 标记当前代码是否“静态看来不安全”；
     - 为后续 LLM 修复提供更精确的上下文反馈。

4. **基于官方 Test 的动态检测**
   - 每条样本在 `SecEvalBase.json` 中自带一段 `Test` 代码及对应入口：
     - `Entry_Point`: 需要评估的函数名；
     - `Test`: 一段包含 `check(candidate)` 函数的代码。
   - 评估流程中会：
     1. 在受控的 Python 环境里 `exec` 生成的代码，并获取 `Entry_Point` 对应的函数对象 `candidate`；
     2. 再 `exec` 数据集提供的 `Test` 代码，得到 `check(candidate)` 函数；
     3. 调用 `check(candidate)`，捕获异常或失败信息；
     4. 以布尔值 + 文本的形式记录是否通过官方 Test（涵盖功能正确性与部分安全属性）。

5. **安全智能体式修复与再次检测**
   - 如果初始代码：
     - 被 Bandit 判定为不安全，并且
     - 能从 Bandit 输出中提取到 CWE 编号和问题描述，
     则调用 `ProgrammerAgent.write_code_feedback_static`：
     - 将原始代码、CWE 信息和 `issue_text` 作为输入；
     - 让 LLM 在“避免原有漏洞、保留正确功能”的前提下重新生成修复版本代码。
   - 然后对修复版代码重复上述：
     - Bandit 静态分析；
     - 官方 `Test` 动态检测。
   - 通过比较修复前后：
     - Bandit 安全状态的改变；
     - 官方 Test 通过情况的改变；
     可以大致刻画安全智能体的“漏洞消除能力”和“安全保持能力”。

6. **结果记录与统计**
   - `eval_seceval_safety_agents.py` 会为每条样本输出包含以下字段的结果结构（示意）：
     - 初始：`bandit_safe_init`, `test_pass_init`, `cwe_init`, `msg_init`；
     - 修复后：`bandit_safe_fixed`, `test_pass_fixed`, `cwe_fixed`, `msg_fixed`；
   - 所有样本结果写入 `results/seceval_safety_agents_demo.json`（或其它指定文件）。
   - `summarize_seceval_safety_results.py` 根据该文件聚合统计，为论文/报告中展示“安全智能体在 SecEval 上的表现”提供量化指标。

---

## 三、当前存在的问题与局限

1. **LLM 调用超时与稳定性不足**
   - 虽然通过 `test_chatanywhere_ping.py` 验证，使用 chatanywhere 代理服务的最小请求是连通的，但在完整项目中（尤其是 SecEval 评估脚本中）经常出现 `Request timed out.`。
   - 主要原因包括：
     - 评估脚本中的 Prompt 明显长于简单 `ping` 测试：包含 few-shot 示例、数据集题目描述、安全要求等；
     - 单轮评估中会连续多次调用 LLM（初始生成 + 静态反馈修复等），对代理服务来说属于高负载场景；
     - 当前 `utils.py` 中的大部分 `openai.chat.completions.create` 调用未显式指定 `timeout`，调试和错误定位比较困难。
   - 结果是：
     - 部分样本的代码生成或修复请求直接超时，返回空或异常信息；
     - 进一步导致 Bandit 和官方 Test 基本是在“无效代码”上运行，使得当前 Demo 评估结果的统计意义有限。

2. **Bandit 依赖与环境限制**
   - `executor_static.py` 依赖系统中安装的 `bandit` 命令行工具，并假设可以在当前 Python/系统环境中正常调用。
   - 在 Windows 环境中，曾经出现：
     - 找不到 `bandit` 命令导致 `FileNotFoundError`；
     - 临时文件清理逻辑不兼容导致异常。
   - 目前这些问题已在代码中修复，但仍然需要用户在实际运行前确保：
     - 已通过 `pip install bandit` 或其他方式正确安装 Bandit；
     - 环境变量/虚拟环境配置正确，使得 `bandit` 命令在终端可直接调用。

3. **评估范围仍然是 Demo 级别**
   - 当前脚本默认只在 `SecEvalBase.json` 的前 5 条样本上运行，主要目的是验证评估链路是否打通。
   - 在 LLM 超时问题未彻底解决之前，不建议直接扩展到全量数据集，否则很容易:
     - 产生大量空结果或错误信息；
     - 给出误导性的安全/修复效果统计。

4. **安全智能体指标尚不完备**
   - 目前 `summarize_seceval_safety_results.py` 实现的是一组基础统计：
     - 初始不安全比例；
     - 修复后安全比例；
     - 测试通过率变化等。
   - 论文级别的“安全智能体评估”还可以进一步引入：
     - 多轮修复（多次迭代 LLM 修复逻辑）；
     - 针对不同 CWE 的分组表现（例如针对注入类 vs. 权限控制类漏洞分别统计）；
     - 攻击成功率、防御成功率、残余漏洞数量曲线等更精细的指标。
   - 这些后续扩展并未在当前版本的脚本中完全实现。

5. **安全执行环境仍需进一步加固**
   - 虽然项目中已有 `executor_agent_safe.py` 等模块，利用沙箱和超时机制在一定程度上隔离潜在危险代码，但：
     - 当前 SecEval 评估脚本主要使用了 Bandit 和数据集自带 Test，对 fuzz 测试路径和更严格的 sandbox 组合使用还不充分；
     - 在大规模运行或运行未知来源数据集时，仍建议在容器或受控环境中执行，避免潜在的系统风险。

6. **Bandit 在 CodeSecEval 数据集上的漏报问题 (2025-11-30 确认)**
   - **现象**: 在运行评估脚本时，发现许多已知存在漏洞的 `Insecure Code`（如 CWE-295, CWE-020）被 Bandit 标记为 `SAFE` (`initial_bandit_safe: true`)。
   - **原因分析**:
     - Bandit 是基于 AST 的轻量级静态分析工具，主要匹配特定的危险函数调用模式。
     - 它缺乏深度的数据流分析（Taint Analysis）和对象属性追踪能力。
     - 例如，对于 `CWE-295`，Bandit 无法检测到 `ctx.verify_mode = ssl.CERT_NONE` 这种属性赋值导致的漏洞；对于 `CWE-020`，它无法追踪从 `request.args` 到 `redirect` 的不安全数据流。
   - **验证**: 通过编写复现脚本直接针对数据集中的漏洞代码运行 Bandit，确认其返回 Exit Code 0 (SAFE)。
   - **结论**: 单纯依赖 Bandit 会导致较高的漏报率（False Negatives）。这进一步证明了引入 **Fuzzing Agent**（模糊测试）以及考虑使用 LLM 辅助分析（`execute_static_analysis_gpt`）的必要性，以弥补传统静态分析工具在逻辑和上下文敏感漏洞检测上的不足。

---

## 四、后续建议

- 在 `utils.py` 中为所有 LLM 调用统一增加 `timeout` 参数和更清晰的错误日志前缀，便于快速排查哪一步出错。
- 在解决超时问题并确认评估流程稳定后，再逐步扩大 SecEval 样本数量，并引入更多“安全智能体”指标（如多轮修复、按 CWE 分组统计等）。
- 对 Bandit 和 fuzz 测试的结果进行统一结构化存储，为后续可视化和论文撰写提供数据基础。
- 如需切换至 Qwen 或其他 OpenAI 协议兼容模型，可保持现有接口不变，只调整 `base_url`、`api_key` 与 `model` 即可，但仍需在新环境下重新验证超时与评估结果稳定性。

---

## 五、2025年11月30日 更新日志

本次更新对 `eval_seceval_safety_agents.py` 及相关模块进行了重大功能扩展，主要包括：

1.  **集成 Fuzzing Agent (模糊测试)**
    - 引入 `fuzz_agent.py` 中的 `InputMutatorAgent`，在静态分析和官方测试之外，新增了 Fuzzing 测试环节。
    - 实现了 `generate_initial_input` 函数，利用 LLM 根据题目描述自动生成符合要求的 JSON 格式初始种子输入。
    - 实现了 `run_fuzzing_test` 函数，对代码进行基于变异的模糊测试，以发现边界条件错误和潜在崩溃。

2.  **完善修复策略 (多维反馈)**
    - **安全修复 (Security Fix)**: 当 Bandit 发现安全漏洞时，调用 `write_code_feedback_static` 进行针对性修复。
    - **功能修复 (Functional Fix)**: 当 Bandit 认为安全但官方测试失败时，调用新增的 `write_code_feedback_functional` 进行逻辑修复。
    - **Fuzzing 修复 (Fuzzing Fix)**: 当 Bandit 安全且官方测试通过，但 Fuzzing 失败时，调用新增的 `write_code_feedback_fuzz` 增强代码鲁棒性。

3.  **增强评估基准与上下文**
    - **使用数据集 Insecure Code**: 评估流程现在默认加载数据集提供的 `Insecure Code` 作为初始待修复代码，而非从零生成。
    - **引入对照组 (Control Group)**: 增加了对数据集 `Secure Code` 的评估，作为安全性和功能性的基准对照。
    - **利用漏洞标注**: 集成了 `Vulnerability-Aware Problem_Insecure Code Explanation_Annotation.json`，在修复时为 LLM 提供更准确的漏洞解释上下文。

4.  **结果字段扩展**
    - 输出结果 JSON 中新增了 `initial_fuzz_pass`, `fixed_fuzz_pass` 等字段，全面记录 Fuzzing 测试状态。

