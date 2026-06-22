#!/usr/bin/env bash
# 第二部分：Triage + Deob + pass2 + LLM Judge（ARK / OpenRouter 兼容协议）
#
# 用法示例（LLM 模式，ARK deepseek-v3-2-251201）：
#   bash run_phase2.sh \
#       --ecosystem pypi \
#       --in-pypi  /home/lyx/code/outpot_pypi/data_pypi3_full \
#       --out-pypi /home/lyx/code/outpot_pypi/data_pypi3_full \
#       --llm-model deepseek-v3-2-251201 \
#       --llm-jobs 8 \
#       --llm-judge --llm-judge-max-slices 30 \
#       --truncate -v
#
# 本地占位模式（不调 LLM）：
#   bash run_phase2.sh --limit 20 --truncate -v
#
# 产物（写回 Phase 1 的同目录）：
#   - slices_v1.jsonl              pass2 切片
#   - per_package_phase2.jsonl     每包完整指标（Triage / Deob / Judge）
#   - phase2_summary.json          聚合统计（含混淆矩阵 TP/FP/TN/FN）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 自动加载 .env（存放 OPENROUTER_API_KEY / OPENROUTER_ENDPOINT 等）
if [ -f "$SCRIPT_DIR/.env" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/.env"
fi

PYBIN="$SCRIPT_DIR/.venv/bin/python"
if [ ! -x "$PYBIN" ]; then
    PYBIN="$(command -v python3)"
fi

# Python -u：强制 stdin/stdout/stderr 不缓冲。
# 否则在 `| tee ...` 管道场景下 print 会被卡在 Python 内部缓冲区，
# 让人误以为程序"卡住了"。
exec "$PYBIN" -u -m malslice.phase2_runner \
    "$@"
