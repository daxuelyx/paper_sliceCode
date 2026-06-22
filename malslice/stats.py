"""实验指标持久化：统一 schema，便于后续绘图 / 制表 / 对照 ground truth。

按用户要求固化以下指标：

基础指标（每包一条记录，写入 `per_package.jsonl`）：
    - package, ecosystem, label (ground_truth 0/1), tarball
    - verdict (预留，Phase 2 LLM 填入), confidence (预留)

Phase 1 级指标（写入 `phase1_summary.json`）：
    - 总包数、成功/失败数
    - 总耗时、平均耗时、P50/P95 分位数
    - 按生态 / 按 label 分别计时

中间过程数据（Phase 2 填入，写入 `phase2_summary.json`）：
    - Triage 命中率：送 LLM 的切片数 / 总切片数
    - obf_class 分布
    - 反混淆成功率、熵变化、LOC 变化
    - 切片统计：avg slices/pkg, Pass1 vs Pass2 增量
    - LLM 指标：tokens, avg response time, json 报错率
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional

from .pipeline import PackageResult, Pass2Metrics


# ----------------------------------------------------------------------
# 每包记录（per-package）
# ----------------------------------------------------------------------

@dataclass
class PackageRecord:
    """单个包的完整画像：Phase 1 写入基础部分，Phase 2 补充 LLM 相关字段。"""
    package: str
    ecosystem: str
    label: Optional[int]               # 1=malicious, 0=benign, None=unknown
    tarball: str

    # Phase 1 输出
    keep_count: int = 0
    dropped_count: int = 0
    pass1_count: int = 0
    dyn_archive_count: int = 0
    elapsed_ms_total: float = 0.0
    elapsed_ms_unpack: float = 0.0
    elapsed_ms_filter: float = 0.0
    elapsed_ms_locate: float = 0.0
    elapsed_ms_slice_pass1: float = 0.0
    errors: List[str] = field(default_factory=list)

    # Phase 2 输出
    pass2_count: int = 0
    triage_total: int = 0
    triage_heuristic_skip: int = 0
    triage_sent_to_llm: int = 0
    triage_json_error: int = 0
    triage_tokens_total: int = 0
    triage_elapsed_ms: float = 0.0
    obf_class_counts: Dict[str, int] = field(default_factory=dict)
    deob_attempted: int = 0
    deob_success: int = 0
    deob_failed: int = 0
    deob_tool_counts: Dict[str, int] = field(default_factory=dict)
    deob_elapsed_ms: float = 0.0
    deob_entropy_delta: List[float] = field(default_factory=list)
    deob_loc_delta: List[int] = field(default_factory=list)
    pass2_elapsed_ms: float = 0.0
    pass2_new_slice_count: int = 0
    reslice_failed_count: int = 0

    # LLM Judge（Phase 2 尾部，当前均留空）
    verdict: Optional[str] = None       # 'malicious' / 'suspicious' / 'benign'
    confidence: Optional[float] = None
    llm_judge_elapsed_ms: float = 0.0
    llm_judge_tokens_total: int = 0
    llm_judge_json_error: int = 0
    llm_judge_categories: List[str] = field(default_factory=list)


# ----------------------------------------------------------------------
# Phase 1：把 PackageResult + 元数据 -> PackageRecord
# ----------------------------------------------------------------------

def record_from_pass1(
    result: PackageResult,
    label: Optional[int],
) -> PackageRecord:
    return PackageRecord(
        package=result.package,
        ecosystem=result.ecosystem,
        label=label,
        tarball=result.tarball,
        keep_count=result.keep_count,
        dropped_count=result.dropped_count,
        pass1_count=result.pass1_count,
        dyn_archive_count=result.dyn_archive_count,
        elapsed_ms_total=result.elapsed_ms_total,
        elapsed_ms_unpack=result.elapsed_ms_unpack,
        elapsed_ms_filter=result.elapsed_ms_filter,
        elapsed_ms_locate=result.elapsed_ms_locate,
        elapsed_ms_slice_pass1=result.elapsed_ms_slice_pass1,
        errors=list(result.errors),
    )


def merge_pass2_metrics(rec: PackageRecord, m: Pass2Metrics, result: PackageResult) -> None:
    rec.pass2_count = result.pass2_count
    rec.triage_total = m.triage_total
    rec.triage_heuristic_skip = m.triage_heuristic_skip
    rec.triage_sent_to_llm = m.triage_sent_to_llm
    rec.triage_json_error = m.triage_json_error
    rec.triage_tokens_total = m.triage_tokens_total
    rec.triage_elapsed_ms = m.triage_elapsed_ms
    rec.obf_class_counts = dict(m.obf_class_counts)
    rec.deob_attempted = m.deob_attempted
    rec.deob_success = m.deob_success
    rec.deob_failed = m.deob_failed
    rec.deob_tool_counts = dict(m.deob_tool_counts)
    rec.deob_elapsed_ms = m.deob_elapsed_ms
    rec.deob_entropy_delta = list(m.deob_entropy_delta)
    rec.deob_loc_delta = list(m.deob_loc_delta)
    rec.pass2_elapsed_ms = m.pass2_elapsed_ms
    rec.pass2_new_slice_count = m.pass2_new_slice_count
    rec.reslice_failed_count = m.reslice_failed_count


# ----------------------------------------------------------------------
# JSONL 追加 / 读取
# ----------------------------------------------------------------------

def append_record(path: str, rec: PackageRecord) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")


def load_records(path: str) -> List[PackageRecord]:
    if not os.path.isfile(path):
        return []
    out: List[PackageRecord] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            out.append(PackageRecord(**d))
    return out


# ----------------------------------------------------------------------
# 聚合统计
# ----------------------------------------------------------------------

def _percentile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    vs = sorted(values)
    k = (len(vs) - 1) * q
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return vs[int(k)]
    return vs[f] + (vs[c] - vs[f]) * (k - f)


def _stats_block(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"count": 0, "sum": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
    return {
        "count": len(values),
        "sum": sum(values),
        "avg": sum(values) / len(values),
        "p50": _percentile(values, 0.5),
        "p95": _percentile(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def summarize_phase1(records: Iterable[PackageRecord]) -> Dict:
    recs = list(records)
    total = len(recs)
    failed = [r for r in recs if r.errors]
    ecosystems = sorted({r.ecosystem for r in recs})
    labels = sorted({r.label for r in recs if r.label is not None})

    times_total = [r.elapsed_ms_total for r in recs]
    slices_per_pkg = [r.pass1_count for r in recs]

    # 按生态分层
    per_eco: Dict[str, Dict] = {}
    for eco in ecosystems:
        sub = [r for r in recs if r.ecosystem == eco]
        per_eco[eco] = {
            "packages": len(sub),
            "failed": sum(1 for r in sub if r.errors),
            "pass1_slices_total": sum(r.pass1_count for r in sub),
            "dyn_archive_total": sum(r.dyn_archive_count for r in sub),
            "time_ms_total": _stats_block([r.elapsed_ms_total for r in sub]),
            "time_ms_unpack": _stats_block([r.elapsed_ms_unpack for r in sub]),
            "time_ms_filter": _stats_block([r.elapsed_ms_filter for r in sub]),
            "time_ms_locate": _stats_block([r.elapsed_ms_locate for r in sub]),
            "time_ms_slice_pass1": _stats_block([r.elapsed_ms_slice_pass1 for r in sub]),
            "slices_per_pkg": _stats_block([float(r.pass1_count) for r in sub]),
        }

    # 按 label 分层
    per_label: Dict[str, Dict] = {}
    for lb in labels:
        sub = [r for r in recs if r.label == lb]
        per_label[str(lb)] = {
            "packages": len(sub),
            "pass1_slices_total": sum(r.pass1_count for r in sub),
            "time_ms_total": _stats_block([r.elapsed_ms_total for r in sub]),
        }

    return {
        "total_packages": total,
        "failed_packages": len(failed),
        "success_rate": (total - len(failed)) / total if total else 0.0,
        "time_ms_total": _stats_block(times_total),
        "slices_per_pkg": _stats_block([float(x) for x in slices_per_pkg]),
        "pass1_slices_total": sum(slices_per_pkg),
        "dyn_archive_total": sum(r.dyn_archive_count for r in recs),
        "per_ecosystem": per_eco,
        "per_label": per_label,
    }


def summarize_phase2(records: Iterable[PackageRecord]) -> Dict:
    recs = list(records)
    total = len(recs)
    triage_totals = sum(r.triage_total for r in recs)
    triage_sent = sum(r.triage_sent_to_llm for r in recs)
    triage_skip = sum(r.triage_heuristic_skip for r in recs)

    obf_dist: Dict[str, int] = {}
    for r in recs:
        for k, v in r.obf_class_counts.items():
            obf_dist[k] = obf_dist.get(k, 0) + v

    # 反混淆
    deob_attempt = sum(r.deob_attempted for r in recs)
    deob_success = sum(r.deob_success for r in recs)
    ent_delta_all: List[float] = []
    loc_delta_all: List[int] = []
    for r in recs:
        ent_delta_all.extend(r.deob_entropy_delta)
        loc_delta_all.extend(r.deob_loc_delta)

    deob_tool_counts: Dict[str, int] = {}
    for r in recs:
        for k, v in r.deob_tool_counts.items():
            deob_tool_counts[k] = deob_tool_counts.get(k, 0) + v

    # 切片增量
    pass1_total = sum(r.pass1_count for r in recs)
    pass2_total = sum(r.pass2_count for r in recs)
    pass2_new = sum(r.pass2_new_slice_count for r in recs)

    # LLM（Triage + Judge 合并）
    llm_tokens = sum(r.triage_tokens_total + r.llm_judge_tokens_total for r in recs)
    llm_json_err = sum(r.triage_json_error + r.llm_judge_json_error for r in recs)
    llm_time_per_pkg = [r.triage_elapsed_ms + r.llm_judge_elapsed_ms for r in recs]

    return {
        "total_packages": total,
        "triage": {
            "slices_total": triage_totals,
            "heuristic_skip": triage_skip,
            "sent_to_llm": triage_sent,
            "llm_hit_rate": (triage_sent / triage_totals) if triage_totals else 0.0,
            "json_error_count": sum(r.triage_json_error for r in recs),
            "obf_class_distribution": obf_dist,
        },
        "deobfuscation": {
            "attempted": deob_attempt,
            "success": deob_success,
            "failed": deob_attempt - deob_success,
            "success_rate": (deob_success / deob_attempt) if deob_attempt else 0.0,
            "tool_counts": deob_tool_counts,
            "entropy_delta": _stats_block(ent_delta_all),
            "loc_delta": _stats_block([float(x) for x in loc_delta_all]),
        },
        "slicing": {
            "pass1_slices_total": pass1_total,
            "pass2_slices_total": pass2_total,
            "pass2_new_slices": pass2_new,
            "pass2_increment_ratio": (pass2_total / pass1_total) if pass1_total else 0.0,
            "avg_pass1_per_pkg": (pass1_total / total) if total else 0.0,
            "avg_pass2_per_pkg": (pass2_total / total) if total else 0.0,
        },
        "llm": {
            "tokens_total": llm_tokens,
            "json_error_total": llm_json_err,
            "json_error_rate": (llm_json_err / total) if total else 0.0,
            "time_ms_per_pkg": _stats_block(llm_time_per_pkg),
        },
        "verdict_distribution": _verdict_distribution(recs),
    }


def _verdict_distribution(recs: List[PackageRecord]) -> Dict:
    """Phase 2 尾部（LLM Judge）若已写入 verdict，则统计分布 + 与 label 对照。

    LLM 未接入时 verdict 全为 None，返回计数即可。
    """
    vd: Dict[str, int] = {}
    for r in recs:
        v = r.verdict or "<none>"
        vd[v] = vd.get(v, 0) + 1
    # 若有 label + verdict，给出简单混淆矩阵
    cm: Dict[str, int] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "UNSCORED": 0}
    for r in recs:
        if r.label is None or r.verdict is None:
            cm["UNSCORED"] += 1
            continue
        pred = 1 if r.verdict == "malicious" else 0
        if r.label == 1 and pred == 1:
            cm["TP"] += 1
        elif r.label == 0 and pred == 1:
            cm["FP"] += 1
        elif r.label == 0 and pred == 0:
            cm["TN"] += 1
        elif r.label == 1 and pred == 0:
            cm["FN"] += 1
    return {"verdict_counts": vd, "confusion_matrix": cm}


def write_summary(path: str, summary: Dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
