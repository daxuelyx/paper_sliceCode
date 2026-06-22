"""malslice CLI：跑通 pass1 + 反混淆 + pass2 切片流水线（跳过 LLM 研判）。

用法参见 README.md。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from typing import Iterator, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from malslice.pipeline import process_package, PackageResult
from malslice.ir import FunctionSlice


DEFAULT_SENSITIVE_CSV = "/home/lyx/code/MalTracker/sensitiveFunc.csv"


# ----------------------------------------------------------------------
# 数据集遍历
# ----------------------------------------------------------------------

def iter_npm_dataset(root: str, label: Optional[str]) -> Iterator[Tuple[str, str]]:
    """yield (tarball_abs_path, package_name_from_filename)"""
    subs = [label] if label else ["mal", "ben"]
    for sub in subs:
        d = os.path.join(root, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".tar.gz") or fn.endswith(".tgz"):
                stem = fn[:-7] if fn.endswith(".tar.gz") else fn[:-4]
                yield os.path.join(d, fn), stem


def iter_pypi_dataset(root: str, label: Optional[str]) -> Iterator[Tuple[str, str]]:
    """yield (path, package_name) — path 可以是 tar.gz 或已解压目录。"""
    subs = [label] if label else ["malicious", "benign"]
    for sub in subs:
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
                        yield os.path.join(ver_dir, fn), stem
                        found_tarball = True
                if not found_tarball:
                    # 已解压目录情形（如 benign 数据集）
                    for fn in sorted(os.listdir(ver_dir)):
                        inner = os.path.join(ver_dir, fn)
                        if os.path.isdir(inner):
                            yield inner, fn


# ----------------------------------------------------------------------
# 单包 / 批量入口
# ----------------------------------------------------------------------

def _write_slices(path: str, slices: List[FunctionSlice], mode: str = "a") -> None:
    with open(path, mode, encoding="utf-8") as f:
        for s in slices:
            f.write(s.to_json() + "\n")


def _write_manifest(path: str, result: PackageResult, label: Optional[str]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "package": result.package,
            "ecosystem": result.ecosystem,
            "tarball": result.tarball,
            "label": label,
            "extract_dir": result.extract_dir,
            "keep_count": result.keep_count,
            "dropped_count": result.dropped_count,
            "pass1_count": result.pass1_count,
            "pass2_count": result.pass2_count,
            "dyn_archive_count": result.dyn_archive_count,
            "deob_summary": result.deob_summary,
            "errors": result.errors,
        }, ensure_ascii=False) + "\n")


def cmd_slice_package(args: argparse.Namespace) -> int:
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    workdir = os.path.join(out_dir, "workdir")
    os.makedirs(workdir, exist_ok=True)

    result, v0, v1, silenced = process_package(
        tarball=os.path.abspath(args.tarball),
        ecosystem=args.ecosystem,
        workdir=workdir,
        package_name=args.package_name,
        sensitive_csv=args.sensitive_csv,
    )

    v0_path = os.path.join(out_dir, "slices_v0.jsonl")
    v1_path = os.path.join(out_dir, "slices_v1.jsonl")
    dyn_path = os.path.join(out_dir, "dyn_probe_archive.jsonl")
    mf_path = os.path.join(out_dir, "manifest.jsonl")

    _write_slices(v0_path, v0, "a")
    _write_slices(v1_path, v1, "a")
    _write_slices(dyn_path, silenced, "a")
    _write_manifest(mf_path, result, label=None)

    print(json.dumps({
        "package": result.package,
        "ecosystem": result.ecosystem,
        "keep": result.keep_count,
        "dropped": result.dropped_count,
        "pass1": result.pass1_count,
        "pass2": result.pass2_count,
        "dyn_silenced": result.dyn_archive_count,
        "deob": result.deob_summary,
        "errors": result.errors,
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    workdir = os.path.join(out_dir, "workdir")
    os.makedirs(workdir, exist_ok=True)

    v0_path = os.path.join(out_dir, "slices_v0.jsonl")
    v1_path = os.path.join(out_dir, "slices_v1.jsonl")
    dyn_path = os.path.join(out_dir, "dyn_probe_archive.jsonl")
    mf_path = os.path.join(out_dir, "manifest.jsonl")

    # 清空旧产物（批量模式）
    if args.truncate:
        for p in (v0_path, v1_path, dyn_path, mf_path):
            if os.path.isfile(p):
                os.remove(p)

    if args.ecosystem == "npm":
        it = iter_npm_dataset(args.dataset, args.label)
    elif args.ecosystem == "pypi":
        it = iter_pypi_dataset(args.dataset, args.label)
    else:
        print(f"unknown ecosystem: {args.ecosystem}", file=sys.stderr)
        return 2

    total_pkgs = 0
    total_v0 = 0
    total_v1 = 0
    total_silent = 0
    failures = 0

    for tarball, stem in it:
        if args.limit and total_pkgs >= args.limit:
            break
        try:
            result, v0, v1, silenced = process_package(
                tarball=tarball,
                ecosystem=args.ecosystem,
                workdir=workdir,
                package_name=stem,
                sensitive_csv=args.sensitive_csv,
            )
            _write_slices(v0_path, v0, "a")
            _write_slices(v1_path, v1, "a")
            _write_slices(dyn_path, silenced, "a")
            _write_manifest(mf_path, result, label=args.label)

            total_pkgs += 1
            total_v0 += len(v0)
            total_v1 += len(v1)
            total_silent += len(silenced)
            if args.verbose:
                print(f"[{total_pkgs}] {result.package}  v0={len(v0)} v1={len(v1)} silent={len(silenced)} deob={result.deob_summary}")
        except Exception as e:
            failures += 1
            if args.verbose:
                traceback.print_exc()
            with open(mf_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "tarball": tarball,
                    "error": f"{type(e).__name__}: {e}",
                }, ensure_ascii=False) + "\n")

    print(json.dumps({
        "processed_packages": total_pkgs,
        "failures": failures,
        "pass1_slices_total": total_v0,
        "pass2_slices_total": total_v1,
        "silenced_dynamic_slices_total": total_silent,
        "out": {
            "slices_v0": v0_path,
            "slices_v1": v1_path,
            "dyn_probe_archive": dyn_path,
            "manifest": mf_path,
        }
    }, ensure_ascii=False, indent=2))
    return 0


# ----------------------------------------------------------------------

def _cmd_phase1(args: argparse.Namespace) -> int:
    from malslice.phase1_runner import main as phase1_main
    argv = [
        "--ecosystem", args.ecosystem,
        "--dataset-npm", args.dataset_npm,
        "--dataset-pypi", args.dataset_pypi,
        "--out-npm", args.out_npm,
        "--out-pypi", args.out_pypi,
        "--sensitive-csv", args.sensitive_csv,
        "--per-package-timeout", str(args.per_package_timeout),
    ]
    if args.label:
        argv += ["--label", args.label]
    if args.limit:
        argv += ["--limit", str(args.limit)]
    if args.truncate:
        argv.append("--truncate")
    if args.keep_extract:
        argv.append("--keep-extract")
    if args.verbose:
        argv.append("-v")
    return phase1_main(argv)


def _cmd_phase2(args: argparse.Namespace) -> int:
    from malslice.phase2_runner import main as phase2_main
    argv = [
        "--ecosystem", args.ecosystem,
        "--in-npm", args.in_npm,
        "--in-pypi", args.in_pypi,
        "--out-npm", args.out_npm,
        "--out-pypi", args.out_pypi,
        "--sensitive-csv", args.sensitive_csv,
    ]
    if args.limit:
        argv += ["--limit", str(args.limit)]
    if args.truncate:
        argv.append("--truncate")
    if args.verbose:
        argv.append("-v")
    return phase2_main(argv)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="malslice", description="NPM / PyPI 恶意包切片引擎（LLM 研判已跳过）")
    sub = p.add_subparsers(dest="cmd", required=True)

    # --- 新：phase1 / phase2（用户当前实验所需） ---
    p_p1 = sub.add_parser("phase1",
                          help="第一部分：首次切片（database_* -> data_*，带时间统计）")
    p_p1.add_argument("--ecosystem", choices=["npm", "pypi", "both"], default="both")
    p_p1.add_argument("--dataset-npm", default="/home/lyx/code/database_npm")
    p_p1.add_argument("--dataset-pypi", default="/home/lyx/code/database_pypi")
    p_p1.add_argument("--out-npm", default="/home/lyx/code/data_npm")
    p_p1.add_argument("--out-pypi", default="/home/lyx/code/data_pypi")
    p_p1.add_argument("--label", default=None,
                      help="限制子集：npm 用 mal/ben；pypi 用 malicious/benign")
    p_p1.add_argument("--limit", type=int, default=0,
                      help="每个 (ecosystem,label) 最多处理 N 个；0=不限")
    p_p1.add_argument("--sensitive-csv", default=DEFAULT_SENSITIVE_CSV)
    p_p1.add_argument("--truncate", action="store_true")
    p_p1.add_argument("--keep-extract", action="store_true",
                      help="保留解压目录（Phase 2 需要可开启）")
    p_p1.add_argument("--per-package-timeout", type=int, default=120,
                      help="单包超时秒数（默认 120s；0=不限）")
    p_p1.add_argument("-v", "--verbose", action="store_true")
    p_p1.set_defaults(func=_cmd_phase1)

    p_p2 = sub.add_parser("phase2",
                          help="第二部分：Triage + Deob + pass2（LLM 已跳过）")
    p_p2.add_argument("--ecosystem", choices=["npm", "pypi", "both"], default="both")
    p_p2.add_argument("--in-npm", default="/home/lyx/code/data_npm")
    p_p2.add_argument("--in-pypi", default="/home/lyx/code/data_pypi")
    p_p2.add_argument("--out-npm", default="/home/lyx/code/data_npm")
    p_p2.add_argument("--out-pypi", default="/home/lyx/code/data_pypi")
    p_p2.add_argument("--sensitive-csv", default=DEFAULT_SENSITIVE_CSV)
    p_p2.add_argument("--limit", type=int, default=0)
    p_p2.add_argument("--truncate", action="store_true")
    p_p2.add_argument("-v", "--verbose", action="store_true")
    p_p2.set_defaults(func=_cmd_phase2)

    # --- 旧：保留 slice-package / run 便于调试 ---
    p1 = sub.add_parser("slice-package", help="对单个 tar.gz 跑完整 pass1+pass2 流水线")
    p1.add_argument("--ecosystem", choices=["npm", "pypi"], required=True)
    p1.add_argument("--tarball", required=True)
    p1.add_argument("--package-name", default=None, help="可选覆盖 name@version；默认取文件名")
    p1.add_argument("--out", default="./out")
    p1.add_argument("--sensitive-csv", default=DEFAULT_SENSITIVE_CSV)
    p1.set_defaults(func=cmd_slice_package)

    p2 = sub.add_parser("run", help="批量在数据集子集上跑通流水线（pass1+pass2 合并版）")
    p2.add_argument("--ecosystem", choices=["npm", "pypi"], required=True)
    p2.add_argument("--dataset", required=True)
    p2.add_argument("--label", default=None)
    p2.add_argument("--out", default="./out")
    p2.add_argument("--limit", type=int, default=0)
    p2.add_argument("--sensitive-csv", default=DEFAULT_SENSITIVE_CSV)
    p2.add_argument("--truncate", action="store_true")
    p2.add_argument("-v", "--verbose", action="store_true")
    p2.set_defaults(func=cmd_run)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
