# malslice - NPM / PyPI 恶意包切片引擎

根据 `/home/lyx/code/rules.md` 的设计蓝图实现的两阶段切片流水线，并按本次实验需求
拆分为 **Phase 1（首次切片）** 与 **Phase 2（Triage + 反混淆 + 二次切片）** 两个独立
入口。

> LLM 研判 / LLM 驱动的反混淆目前**按用户要求跳过**，但全部 LLM 相关指标字段（token、
> latency、json_error、verdict、confidence）均已在 IR 与统计 schema 中预留，后续接入
> LLM 时只需替换 `malslice.phase2_runner.llm_triage_fn` /
> `malslice.phase2_runner.llm_deob_fn` / `malslice.phase2_runner.llm_judge_package` 三个函数。

---

## 目录结构

```
sliceCode/
├── README.md
├── requirements.txt
├── run.py                       # 总 CLI 入口
├── run_phase1.sh                # 一键跑 Phase 1
├── run_phase2.sh                # 一键跑 Phase 2
└── malslice/
    ├── ir.py                    # FunctionSlice 数据类（§3）
    ├── utils.py                 # 熵、语言识别、行窗口
    ├── unpacker.py              # §4.1
    ├── noise_filter.py          # §4.2
    ├── entry_point.py           # §4.3
    ├── sink_registry.py         # §4.6
    ├── obfuscation_triage.py    # §4.4（启发式 + 指纹，LLM 已跳过）
    ├── deobfuscator.py          # §4.5（Python AST 常量链 + JS eval_string 兜底）
    ├── slicer_py.py             # §4.7 Python Slicer
    ├── slicer_js.py             # §4.7 JS Slicer (esprima)
    ├── pipeline.py              # pass1_only / pass2_flow / process_package
    ├── stats.py                 # 指标 schema + 聚合
    ├── phase1_runner.py         # Phase 1 批处理
    └── phase2_runner.py         # Phase 2 批处理（含 LLM 占位）
```

---

## 安装

```bash
cd /home/lyx/code/sliceCode
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

---

## 第一部分：首次切片（Phase 1）

**目标**：对 `/home/lyx/code/database_npm` 与 `/home/lyx/code/database_pypi` 下的所有包
执行 pass1_only（Unpack → Filter → Locate → Slicer pass1 + 兜底 A/G + FP 缓释），
并把结果分别写到 `/home/lyx/code/data_npm` 与 `/home/lyx/code/data_pypi`，同时统计
**时间消耗**。

### 一键跑

```bash
# 全量
bash /home/lyx/code/sliceCode/run_phase1.sh

# 冒烟（每个 ecosystem × label 只处理 50 个）
bash /home/lyx/code/sliceCode/run_phase1.sh --limit 50

# 只跑 PyPI malicious
bash /home/lyx/code/sliceCode/run_phase1.sh --ecosystem pypi --label malicious

# 覆盖旧产物（默认追加，便于断点续跑）
bash /home/lyx/code/sliceCode/run_phase1.sh --truncate
```

等价的直接调用：

```bash
./.venv/bin/python -m malslice.phase1_runner \
    --ecosystem both \
    --dataset-npm  /home/lyx/code/database_npm \
    --dataset-pypi /home/lyx/code/database_pypi \
    --out-npm      /home/lyx/code/data_npm \
    --out-pypi     /home/lyx/code/data_pypi \
    --per-package-timeout 120 \
    -v
```

### Phase 1 产物

| 路径 | 说明 |
|---|---|
| `data_npm/slices_v0.jsonl`、`data_pypi/slices_v0.jsonl` | 全量 pass1 切片（每行一条 FunctionSlice） |
| `data_*/dyn_probe_archive.jsonl` | §4.6.x FP 缓释静默归档 |
| `data_*/per_package.jsonl` | **每包基础记录**：label、切片数、各阶段耗时、errors |
| `data_*/phase1_summary.json` | **聚合统计**：总耗时、平均/中位数/P95、按生态/label 分层 |
| `data_*/workdir/<pkg>/` | 解压产物（默认运行完删除；用 `--keep-extract` 保留） |

### Phase 1 统计的"时间消耗"包含

- 每包总耗时 `elapsed_ms_total` 与各阶段耗时：`unpack / filter / locate / slice_pass1`
- 聚合层提供：sum、avg、p50、p95、min、max
- 分层：按生态（npm/pypi）和 label（0=benign, 1=malicious）分别给出上述时间分布

---

## 第二部分：Triage + 反混淆 + 二次切片（Phase 2）

Phase 2 读取 Phase 1 产物，依次做：

1. **ObfuscationTriage（§4.4）**：
   - §4.4.1 启发式前置剪枝（6 维）始终本地执行；
   - 6 维任一触发的切片 → 走 **OpenRouter LLM**（若配置了 `--llm-model` + `OPENROUTER_API_KEY`），
     返回 `obf_class / confidence / target_file_needed`（§8.2 Prompt，严格 JSON，
     失败自动 1 次低温重试，再失败 fallback 启发式指纹分类器并打 `json_error=True`）；
   - 未配置 LLM 时，仍用本地指纹分类器占位。
2. **Deobfuscator（§4.5）**：按 `rules.md` 原则"LLM 不直接产出反混淆结果"——始终走内置
   工具链（Python AST 常量链 + JS eval_string 折叠）。若今后改为 LLM Agent 驱动
   工具选择，只需替换 `malslice/phase2_runner.py :: llm_deob_fn`。
3. **Slicer pass2（§4.7.x）**：在反混淆文件上复用 pass1 Slicer。
4. **LLM Judge（§4.8）**：仍为占位（`verdict=None`）；第三部分启用。

### 模式 1：LLM Triage（生产模式，走 OpenRouter）

```bash
# 1) 准备 OpenRouter Key（https://openrouter.ai/keys）
export OPENROUTER_API_KEY=sk-or-xxxxxxxxxxxxx
# 可选：export OPENROUTER_APP_NAME="malslice"

# 2) 冒烟 20 个包（LLM 调用 + 统计 token/延迟/json_err）
bash /home/lyx/code/sliceCode/run_phase2.sh \
    --llm-model "deepseek/deepseek-v4-flash" \
    --llm-jobs 4 \
    --limit 20 --truncate -v

# 3) 满意后全量
bash /home/lyx/code/sliceCode/run_phase2.sh \
    --llm-model "deepseek/deepseek-v4-flash" \
    --llm-jobs 8 \
    --truncate -v
```

其他可选旋钮：`--llm-max-tokens`（默认 512）、`--llm-timeout`（默认 60s）、
`--ecosystem npm|pypi|both`、`--limit N`。

### 模式 2：本地占位（不调 LLM、0 token，用于回归测试）

```bash
bash /home/lyx/code/sliceCode/run_phase2.sh --limit 50 --truncate -v
```

### Phase 2 产物

| 路径 | 说明 |
|---|---|
| `data_*/slices_v1.jsonl` | pass2 切片（`reslice_version=1`） |
| `data_*/per_package_phase2.jsonl` | 每包**完整**记录：Phase 1 字段 + Triage / Deob / LLM 指标 |
| `data_*/phase2_summary.json` | Phase 2 聚合统计 |

---

## 总体实验统计的指标（与用户要求对齐）

### 基础指标（`per_package.jsonl` / `per_package_phase2.jsonl` 的每行）

- `label`（Ground Truth，1=malicious / 0=benign）
- `verdict`（LLM Judge 输出；当前为 `null`）
- `confidence`（LLM Judge 置信度；当前为 `null`）
- `tarball`、`package`、`ecosystem`

### 中间过程数据

| 指标 | 字段来源 |
|---|---|
| **Triage 命中率** = 送 LLM 的切片数 / 总切片数 | 每包 `triage_sent_to_llm / triage_total`；聚合字段 `phase2_summary.json.triage.llm_hit_rate` |
| **各混淆类别分布** | 每包 `obf_class_counts`；聚合 `phase2_summary.json.triage.obf_class_distribution` |
| **反混淆成功率** | 聚合 `phase2_summary.json.deobfuscation.success_rate` |
| **反混淆前后熵变化** | 每包 `deob_entropy_delta`（列表，每个反混淆文件一条：`old - new`）；聚合 `phase2_summary.json.deobfuscation.entropy_delta.{avg,p50,p95,...}` |
| **反混淆前后 LOC 变化** | 每包 `deob_loc_delta`；聚合同上 |
| **切片统计** | `phase2_summary.json.slicing`：`avg_pass1_per_pkg` / `avg_pass2_per_pkg` / `pass2_increment_ratio` / `pass2_new_slices` |
| **Pass1 vs Pass2 增量** | `pass1_slices_total` vs `pass2_slices_total`、`pass2_new_slices`（pass2 中 `parent_slice_id=null` 的新增切片数） |

### LLM 指标（目前均为占位 0）

| 指标 | 字段来源 |
|---|---|
| **Token 消耗总量** | `per_package.triage_tokens_total + llm_judge_tokens_total`；聚合 `phase2_summary.json.llm.tokens_total` |
| **平均单包响应时间** | `per_package.triage_elapsed_ms + llm_judge_elapsed_ms`；聚合 `phase2_summary.json.llm.time_ms_per_pkg` |
| **JSON 格式报错率** | `per_package.triage_json_error + llm_judge_json_error`；聚合 `phase2_summary.json.llm.json_error_rate` |

### 时间消耗（Phase 1 重点）

- **单阶段**：`elapsed_ms_unpack / filter / locate / slice_pass1 / triage / deob / slice_pass2`
- **单包总耗时**：`elapsed_ms_total`
- **聚合统计**：`phase1_summary.json.time_ms_*.{avg, p50, p95, min, max, sum, count}`
- **按生态 / label 分层**：`phase1_summary.json.per_ecosystem / per_label`

---

## 调试子命令（旧）

```bash
# 单包
./.venv/bin/python run.py slice-package --ecosystem npm --tarball <path>.tar.gz --out ./out

# 批量（旧，合并 pass1+pass2）
./.venv/bin/python run.py run --ecosystem pypi --dataset /home/lyx/code/database_pypi --label malicious --out ./out --limit 20 --truncate -v
```
