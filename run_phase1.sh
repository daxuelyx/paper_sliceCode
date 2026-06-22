#!/usr/bin/env bash
# 一键执行：第一部分（首次切片 pass1_only）。
#
# 输入： /home/lyx/code/database_npm  + /home/lyx/code/database_pypi
# 输出： /home/lyx/code/data_npm       + /home/lyx/code/data_pypi
#        - slices_v0.jsonl               全量 pass1 切片
#        - dyn_probe_archive.jsonl       FP 缓释静默归档
#        - per_package.jsonl             每包基础记录（含时间戳、ground truth label）
#        - phase1_summary.json           聚合统计（时间、切片数、按生态/label 分层）
#        - workdir/<pkg>/                解压产物（--keep-extract 才保留）
#
# 用法：
#   bash run_phase1.sh              # 全量跑（可能耗时数小时）
#   bash run_phase1.sh --limit 50   # 每个 (ecosystem,label) 只跑 50 个，快速冒烟
#   bash run_phase1.sh --ecosystem pypi --label malicious
#   bash run_phase1.sh --truncate   # 覆盖上次产物（默认追加，断点续跑更方便）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 使用随模块自带的 venv；找不到则退回系统 python3
PYBIN="$SCRIPT_DIR/.venv/bin/python"
if [ ! -x "$PYBIN" ]; then
    echo "[warn] venv 未初始化，尝试用系统 python3"
    PYBIN="$(command -v python3)"
fi

echo "[info] Python : $PYBIN"
echo "[info] CWD    : $SCRIPT_DIR"
echo "[info] args   : $*"
echo "[info] 启动 Phase 1..."

exec "$PYBIN" -u -m malslice.phase1_runner \
    --ecosystem both \
    --dataset-npm  /home/lyx/code/database_npm \
    --dataset-pypi /home/lyx/code/database_pypi \
    --out-npm      /home/lyx/code/data_npm2 \
    --out-pypi     /home/lyx/code/data_pypi2 \
    --per-package-timeout 120 \
    -v \
    "$@"
