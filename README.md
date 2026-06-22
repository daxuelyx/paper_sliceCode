# malslice - NPM / PyPI 恶意包切片引擎

根据 `../rules.md` 的设计蓝图实现的两阶段切片流水线，并按本次实验需求
拆分为 **Phase 1（首次切片）** 与 **Phase 2（Triage + 反混淆 + 二次切片）** 两个独立
入口。

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
cd ../sliceCode
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

---

## 第一部分：首次切片（Phase 1）

### 一键跑

```bash
# 全量
bash ../sliceCode/run_phase1.sh

# 冒烟（每个 ecosystem × label 只处理 50 个）
bash ../sliceCode/run_phase1.sh --limit 50

# 只跑 PyPI malicious
bash ../sliceCode/run_phase1.sh --ecosystem pypi --label malicious

# 覆盖旧产物（默认追加，便于断点续跑）
bash ../sliceCode/run_phase1.sh --truncate
```

等价的直接调用：

```bash
./.venv/bin/python -m malslice.phase1_runner \
    --ecosystem both \
    --dataset-npm  ../database_npm \
    --dataset-pypi ../database_pypi \
    --out-npm      ../data_npm \
    --out-pypi     ../data_pypi \
    --per-package-timeout 120 \
    -v
```


## 第二部分：Triage + 反混淆 + 二次切片（Phase 2）

Phase 2 读取 Phase 1 产物：

```bash
# 1) 准备 OpenRouter Key（https://openrouter.ai/keys）
export OPENROUTER_API_KEY=sk-or-xxxxxxxxxxxxx
# 可选：export OPENROUTER_APP_NAME="malslice"

# 2) 冒烟 20 个包（LLM 调用 + 统计 token/延迟/json_err）
bash ../sliceCode/run_phase2.sh \
    --llm-model "deepseek/deepseek-v4-flash" \
    --llm-jobs 4 \
    --limit 20 --truncate -v

# 3) 满意后全量
bash ../sliceCode/run_phase2.sh \
    --llm-model "deepseek/deepseek-v4-flash" \
    --llm-jobs 8 \
    --truncate -v
```

其他可选旋钮：`--llm-max-tokens`（默认 512）、`--llm-timeout`（默认 60s）、
`--ecosystem npm|pypi|both`、`--limit N`