"""Phase 1：首次切片（pass1_only）。

输入：
  - `/home/lyx/code/database_npm/{mal,ben}`
  - `/home/lyx/code/database_pypi/{malicious,benign}`

输出（默认路径）：
  - `/home/lyx/code/data_npm/slices_v0.jsonl`        # pass1 切片全量
  - `/home/lyx/code/data_npm/dyn_probe_archive.jsonl` # FP 缓释静默归档
  - `/home/lyx/code/data_npm/per_package.jsonl`       # 每包基础记录（含时间）
  - `/home/lyx/code/data_npm/phase1_summary.json`     # 聚合统计
  - `/home/lyx/code/data_npm/workdir/<pkg>/`          # 解压产物
  - 同结构写到 `/home/lyx/code/data_pypi/`

Phase 2 会直接消费 `per_package.jsonl` 与 `slices_v0.jsonl`。
"""
from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sys
import time
import traceback
from dataclasses import asdict
from typing import Iterator, List, Optional, Tuple

from .ir import FunctionSlice
from .pipeline import Pass1Artifact, pass1_only
from .stats import (
    PackageRecord,
    append_record,
    load_records,
    record_from_pass1,
    summarize_phase1,
    write_summary,
)


DEFAULT_SENSITIVE_CSV = "/home/lyx/code/MalTracker/sensitiveFunc.csv"


# ======================================================================
# 数据集遍历
# ======================================================================

def iter_npm_dataset(root: str, label: Optional[str]) -> Iterator[Tuple[str, str, int, str]]:
    """yield (tarball_path, package_stem, label_01, label_str)"""
    label_map = {"mal": 1, "ben": 0}
    subs = [label] if label else ["mal", "ben"]
    for sub in subs:
        if sub not in label_map:
            continue
        d = os.path.join(root, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".tar.gz") or fn.endswith(".tgz"):
                stem = fn[:-7] if fn.endswith(".tar.gz") else fn[:-4]
                yield os.path.join(d, fn), stem, label_map[sub], sub


def iter_pypi_dataset(root: str, label: Optional[str]) -> Iterator[Tuple[str, str, int, str]]:
    label_map = {"malicious": 1, "benign": 0}
    subs = [label] if label else ["malicious", "benign"]
    for sub in subs:
        if sub not in label_map:
            continue
        d = os.path.join(root, sub)
        if not os.path.isdir(d):
            continue
        for pkg in sorted(os.listdir(d)):
            pkg_dir = os.path.join(d, pkg)
            if not os.path.isdir(pkg_dir):
                continue
            for ver in sorted(os.listdir(pkg_dir)):
                ver_dir = os.path.join(pkg_dir, ver)
                if not os.path.isdir(ver_dir):
                    continue
                found_tarball = False
                for fn in sorted(os.listdir(ver_dir)):
                    if fn.endswith(".tar.gz") or fn.endswith(".tgz"):
                        stem = fn[:-7] if fn.endswith(".tar.gz") else fn[:-4]
                        yield os.path.join(ver_dir, fn), stem, label_map[sub], sub
                        found_tarball = True
                if not found_tarball:
                    # 已解压目录（benign 数据集常见）
                    for fn in sorted(os.listdir(ver_dir)):
                        inner = os.path.join(ver_dir, fn)
                        if os.path.isdir(inner):
                            yield inner, fn, label_map[sub], sub


# ======================================================================
# 工作线程：对单包调用 pass1_only 并落盘
# ======================================================================

def _run_single_package(
    tarball: str,
    ecosystem: str,
    stem: str,
    label: int,
    workdir: str,
    sensitive_csv: str,
    slice_out_path: str,
    dyn_out_path: str,
    record_out_path: str,
    keep_extract: bool,
) -> PackageRecord:
    artifact: Pass1Artifact = pass1_only(
        tarball=tarball,
        ecosystem=ecosystem,
        workdir=workdir,
        package_name=stem,
        sensitive_csv=sensitive_csv,
    )
    # 落盘切片
    with open(slice_out_path, "a", encoding="utf-8") as f:
        for s in artifact.pass1_slices:
            f.write(s.to_json() + "\n")
    with open(dyn_out_path, "a", encoding="utf-8") as f:
        for s in artifact.silenced_slices:
            f.write(s.to_json() + "\n")

    rec = record_from_pass1(artifact.result, label=label)
    append_record(record_out_path, rec)

    # 若无需保留，把解压目录删掉以省空间（解压目录只在 Phase 2 需要，缺省保留）
    if not keep_extract and not os.path.isdir(tarball):
        # 只清理 pass1_only 解压的产物（tarball 路径 != extract_dir 时才是解压产物）
        import shutil
        extract_dir = artifact.result.extract_dir
        if os.path.isdir(extract_dir) and extract_dir.startswith(os.path.abspath(workdir)):
            shutil.rmtree(extract_dir, ignore_errors=True)
    return rec


# ======================================================================
# CLI 入口
# ======================================================================

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phase1",
        description="Phase 1：首次切片（pass1_only），带全量时间/大小/切片数统计",
    )
    p.add_argument("--ecosystem", choices=["npm", "pypi", "both"], default="both")
    p.add_argument("--dataset-npm", default="/home/lyx/code/database_npm")
    p.add_argument("--dataset-pypi", default="/home/lyx/code/database_pypi")
    p.add_argument("--out-npm", default="/home/lyx/code/data_npm")
    p.add_argument("--out-pypi", default="/home/lyx/code/data_pypi")
    p.add_argument("--label", default=None,
                   help="限制子集：npm 用 mal/ben；pypi 用 malicious/benign；留空 = 全跑")
    p.add_argument("--limit", type=int, default=0,
                   help="每个 (ecosystem,label) 最多处理 N 个；0 = 不限")
    p.add_argument("--sensitive-csv", default=DEFAULT_SENSITIVE_CSV)
    p.add_argument("--truncate", action="store_true",
                   help="覆盖旧产物（默认追加，便于断点续跑）")
    p.add_argument("--keep-extract", action="store_true",
                   help="保留解压目录（默认删除以省磁盘；Phase 2 需要时请开启）")
    p.add_argument("--per-package-timeout", type=int, default=0,
                   help="单包超时秒数；0=不限制。超时视为失败并继续")
    p.add_argument("--random-sample", action="store_true",
                   help="每个 (ecosystem,label) 从数据集**随机**抽 --limit 个，配合 --seed")
    p.add_argument("--seed", type=int, default=42,
                   help="随机采样的种子（默认 42，保证可复现）")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _prep_out(root: str, truncate: bool) -> dict:
    os.makedirs(root, exist_ok=True)
    workdir = os.path.join(root, "workdir")
    os.makedirs(workdir, exist_ok=True)
    paths = {
        "slices_v0": os.path.join(root, "slices_v0.jsonl"),
        "dyn_probe": os.path.join(root, "dyn_probe_archive.jsonl"),
        "per_package": os.path.join(root, "per_package.jsonl"),
        "summary": os.path.join(root, "phase1_summary.json"),
        "workdir": workdir,
    }
    if truncate:
        for key in ("slices_v0", "dyn_probe", "per_package", "summary"):
            p = paths[key]
            if os.path.isfile(p):
                os.remove(p)
    return paths


class _TimeoutError(Exception):
    pass


def _timeout_handler(signum, frame):
    raise _TimeoutError("per-package timeout")


def _run_with_timeout(fn, timeout: int, *args, **kwargs):
    if timeout <= 0:
        return fn(*args, **kwargs)
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout)
    try:
        return fn(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _run_one_ecosystem(
    ecosystem: str,
    dataset_root: str,
    out_root: str,
    label_filter: Optional[str],
    limit: int,
    sensitive_csv: str,
    truncate: bool,
    keep_extract: bool,
    verbose: bool,
    per_package_timeout: int,
    random_sample: bool = False,
    seed: int = 42,
) -> Tuple[int, int, float]:
    paths = _prep_out(out_root, truncate)
    t_start = time.perf_counter()

    if ecosystem == "npm":
        it = iter_npm_dataset(dataset_root, label_filter)
    elif ecosystem == "pypi":
        it = iter_pypi_dataset(dataset_root, label_filter)
    else:
        return 0, 0, 0.0

    # 随机采样：先把所有 item 列出来，按 label 分桶，再每桶随机挑 limit 个
    sampled: List[Tuple] = []
    if random_sample and limit > 0:
        all_items = list(it)
        by_label: dict = {}
        for tup in all_items:
            by_label.setdefault(tup[3], []).append(tup)
        rng = random.Random(seed)
        for label_name, bucket in by_label.items():
            rng.shuffle(bucket)
            picked = bucket[:limit]
            sampled.extend(picked)
            print(f"  [sample] {ecosystem}/{label_name}: {len(picked)}/{len(bucket)} "
                  f"(seed={seed})", flush=True)
        # 混排不同 label，避免 phase2 在 `--limit` 情况下只吃到 mal
        rng.shuffle(sampled)
        it = iter(sampled)

    # 预估总数（随机采样模式下 = sampled 长度；否则未知）
    total_expected = len(sampled)

    n_processed = 0
    n_failed = 0
    # 按 label 分桶以支持 --limit
    per_label_count: dict = {}

    for tarball, stem, label, label_name in it:
        # 随机采样模式下 limit 已在采样阶段生效，这里不再二次限制
        if (not random_sample) and limit and per_label_count.get(label_name, 0) >= limit:
            # 继续枚举其他 label
            continue
        per_label_count[label_name] = per_label_count.get(label_name, 0) + 1

        t0 = time.perf_counter()
        try:
            rec = _run_with_timeout(
                _run_single_package,
                per_package_timeout,
                tarball=tarball,
                ecosystem=ecosystem,
                stem=stem,
                label=label,
                workdir=paths["workdir"],
                sensitive_csv=sensitive_csv,
                slice_out_path=paths["slices_v0"],
                dyn_out_path=paths["dyn_probe"],
                record_out_path=paths["per_package"],
                keep_extract=keep_extract,
            )
            n_processed += 1
            if verbose:
                idx_str = f"[{n_processed}/{total_expected}]" if total_expected else f"[#{n_processed}]"
                if total_expected and n_processed > 0:
                    elapsed = time.perf_counter() - t_start
                    eta_s = elapsed / n_processed * (total_expected - n_processed)
                    eta_str = f"ETA={eta_s/60:.1f}min"
                else:
                    eta_str = ""
                print(f"{idx_str} [{ecosystem}][{label_name}] {stem}  "
                      f"keep={rec.keep_count} slices={rec.pass1_count} "
                      f"t={rec.elapsed_ms_total:.0f}ms  {eta_str}", flush=True)
        except _TimeoutError:
            n_failed += 1
            _append_failure(paths["per_package"], tarball, stem, ecosystem, label,
                            f"timeout_after_{per_package_timeout}s")
            if verbose:
                print(f"[{ecosystem}][{label_name}] {stem}  TIMEOUT")
        except Exception as e:
            n_failed += 1
            err = f"{type(e).__name__}: {e}"
            if verbose:
                traceback.print_exc()
            _append_failure(paths["per_package"], tarball, stem, ecosystem, label, err)

    elapsed = time.perf_counter() - t_start

    # 读回 per-package，写聚合 summary
    recs = load_records(paths["per_package"])
    summary = summarize_phase1(recs)
    summary["ecosystem"] = ecosystem
    summary["dataset_root"] = dataset_root
    summary["wall_clock_seconds"] = elapsed
    summary["processed_in_this_run"] = n_processed
    summary["failed_in_this_run"] = n_failed
    write_summary(paths["summary"], summary)
    return n_processed, n_failed, elapsed


def _append_failure(per_package_path: str, tarball: str, stem: str,
                    ecosystem: str, label: int, err: str) -> None:
    rec = PackageRecord(
        package=stem, ecosystem=ecosystem, label=label, tarball=tarball,
        errors=[err],
    )
    append_record(per_package_path, rec)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    targets: List[Tuple[str, str, str]] = []
    if args.ecosystem in ("npm", "both"):
        targets.append(("npm", args.dataset_npm, args.out_npm))
    if args.ecosystem in ("pypi", "both"):
        targets.append(("pypi", args.dataset_pypi, args.out_pypi))

    t_all = time.perf_counter()
    agg = {}
    for eco, ds, outr in targets:
        print(f"\n=== Phase 1: {eco}  dataset={ds}  out={outr} ===")
        nok, nfail, elap = _run_one_ecosystem(
            ecosystem=eco,
            dataset_root=ds,
            out_root=outr,
            label_filter=args.label,
            limit=args.limit,
            sensitive_csv=args.sensitive_csv,
            truncate=args.truncate,
            keep_extract=args.keep_extract,
            verbose=args.verbose,
            per_package_timeout=args.per_package_timeout,
            random_sample=args.random_sample,
            seed=args.seed,
        )
        agg[eco] = {"processed": nok, "failed": nfail, "seconds": elap}

    total_wall = time.perf_counter() - t_all
    print("\n=== Phase 1 DONE ===")
    print(json.dumps({
        "wall_clock_seconds": total_wall,
        "per_ecosystem": agg,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
