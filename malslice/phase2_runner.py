"""Phase 2：Triage + Deobfuscator + Pass2。

现支持两种 Triage 模式：
  - **启发式模式**（未设 `--llm-model` 或无 `OPENROUTER_API_KEY`）：
    §4.4.1 6 维启发式 + 指纹分类器，完全本地。
  - **LLM 模式**（`--llm-model <name>` + 设置了 `OPENROUTER_API_KEY`）：
    §4.4 完整两段——启发式前置剪枝保持本地；6 维任一触发的切片批量走
    OpenRouter（OpenAI 兼容协议），严格 JSON 解析 + 1 次低温重试；
    每次调用的 prompt/completion tokens、延迟、json_error 全部计入指标。

Deobfuscator 按 §4.5 的原则"LLM 不直接产出反混淆结果、只给 obf_class"，因此
`llm_deob_fn` 依旧走内置工具链（Python AST 常量链 + JS eval_string 折叠）。
今后若要引入 LLM Agent 驱动反混淆工具选择，只需替换 `llm_deob_fn`。

指标落盘见 `stats.py`。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from dataclasses import asdict
from typing import Callable, Dict, List, Optional

from .ir import FunctionSlice
from .pipeline import Pass1Artifact, pass1_only, pass2_flow
from .stats import (
    PackageRecord,
    append_record,
    load_records,
    merge_pass2_metrics,
    summarize_phase2,
    write_summary,
)
from .obfuscation_triage import triage_slice as heuristic_triage
from .llm_client import OpenRouterClient, build_client_from_env, parallel_map


DEFAULT_SENSITIVE_CSV = "/home/lyx/code/MalTracker/sensitiveFunc.csv"


# ----------------------------------------------------------------------
# §8.2 ObfuscationTriage Prompt
# ----------------------------------------------------------------------

TRIAGE_SYSTEM = (
    "你是一名静态代码混淆分析师。只判断给定切片是否经过混淆 / 加密 / 编码，"
    "并分类到固定枚举；不需要做恶意性判断。严格输出 JSON。"
)

TRIAGE_USER_TEMPLATE = """Ecosystem : {ecosystem}
Package   : {package}
File      : {file}
Sink(s)   : {sink}
Heuristics: {hints}

--- IMPORTS ---
{imports}

--- SLICE SOURCE ---
{source_code}

--- LOCAL CALLEES (1-hop) ---
{callees_inline}

请严格按照如下 JSON 返回（不得输出其它文本）：
{{
  "obf_class": "jsobf_stringarray|webpack_bundle|jsfuck|aaencode|eval_string|pyarmor|pyc_marshal|b64_chain|hex_chain|zlib_chain|mixed_heavy|none",
  "confidence": float,
  "target_file_needed": bool,
  "reason": "一句话解释为什么归入该类"
}}"""


VALID_OBF_CLASSES = {
    "jsobf_stringarray", "webpack_bundle", "jsfuck", "aaencode",
    "eval_string", "pyarmor", "pyc_marshal",
    "b64_chain", "hex_chain", "zlib_chain", "mixed_heavy", "none",
}


def _truncate(text: str, max_chars: int = 4000) -> str:
    """避免单条 Prompt 失控。对超长切片做 head+tail 截断，保留首尾各一半。"""
    if not text or len(text) <= max_chars:
        return text or ""
    half = max_chars // 2
    return text[:half] + f"\n/* ... truncated {len(text) - max_chars} chars ... */\n" + text[-half:]


def _build_triage_user_prompt(slice_obj: FunctionSlice) -> str:
    # 压缩 hints（避免把一堆无关字段喂进去）
    keep_keys = {
        "entropy", "max_line_len", "avg_id_len", "eval_count",
        "has_fingerprint", "large_encoded_literal",
    }
    hints = {k: v for k, v in slice_obj.confidence_hint.items() if k in keep_keys}

    imports_txt = "\n".join(slice_obj.imports)[:1500]
    callees_txt = "\n".join(slice_obj.callees_inline)[:2500]

    return TRIAGE_USER_TEMPLATE.format(
        ecosystem=slice_obj.ecosystem,
        package=slice_obj.package,
        file=slice_obj.file,
        sink=",".join(slice_obj.sink),
        hints=json.dumps(hints, ensure_ascii=False),
        imports=_truncate(imports_txt, 1500),
        source_code=_truncate(slice_obj.source_code, 4000),
        callees_inline=_truncate(callees_txt, 2500),
    )


# ----------------------------------------------------------------------
# Triage 实现：启发式本地 + （可选）LLM
# ----------------------------------------------------------------------

def _local_heuristic_result(slice_obj: FunctionSlice) -> Dict:
    res = heuristic_triage(slice_obj)
    return {
        "obf_class": res.obf_class,
        "confidence": res.confidence,
        "target_file_needed": res.target_file_needed,
        "triage_source": res.triage_source,
        "reason": res.reason,
        "hints": res.hints,
        "tokens": 0,
        "json_error": False,
        "latency_ms": 0.0,
    }


def _call_llm_triage_one(
    slice_obj: FunctionSlice,
    client: OpenRouterClient,
) -> Dict:
    """对一条需要 LLM 判型的切片调 OpenRouter 并返回规范化结果。"""
    user_prompt = _build_triage_user_prompt(slice_obj)
    call = client.chat_json(TRIAGE_SYSTEM, user_prompt)

    base_hints = dict(slice_obj.confidence_hint)  # 已由启发式填好
    if not call.ok or call.parsed is None:
        # 兜底：用启发式 + 指纹的结论，但 source 标为 llm，json_error 计数
        local = _local_heuristic_result(slice_obj)
        local["triage_source"] = "llm"
        local["json_error"] = call.json_error or True
        local["tokens"] = call.total_tokens or (call.prompt_tokens + call.completion_tokens)
        local["latency_ms"] = call.latency_ms
        local["reason"] = f"llm_failed_fallback_to_heuristic: {call.error or 'parse_error'}"
        return local

    parsed = call.parsed
    obf_class = parsed.get("obf_class", "none")
    if obf_class not in VALID_OBF_CLASSES:
        obf_class = "none"
    try:
        conf = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    # §4.4.3：confidence < 0.4 视为 none
    if obf_class != "none" and conf < 0.4:
        obf_class = "none"

    return {
        "obf_class": obf_class,
        "confidence": conf,
        "target_file_needed": bool(parsed.get("target_file_needed", False)),
        "triage_source": "llm",
        "reason": str(parsed.get("reason", ""))[:300],
        "hints": base_hints,  # 启发式已填的 hints 继续保留
        "tokens": call.total_tokens or (call.prompt_tokens + call.completion_tokens),
        "json_error": False,
        "latency_ms": call.latency_ms,
    }


def make_triage_cache_for_artifact(
    artifact: Pass1Artifact,
    llm_client: Optional[OpenRouterClient],
    n_workers: int,
    verbose: bool = False,
) -> Dict[str, Dict]:
    """对一包的所有 pass1 切片预计算 triage 结果（必要时并发调 LLM）。

    返回 {slice_id: triage_result_dict}，随后注入 pass2_flow 的 triage_fn。
    """
    slices = artifact.pass1_slices
    # 第一步：全部跑本地启发式
    local_results: Dict[str, Dict] = {}
    candidates_for_llm: List[FunctionSlice] = []
    for s in slices:
        r = _local_heuristic_result(s)
        # 原 obfuscation_triage.triage_slice 里：
        #   6 维都不触发 -> triage_source=heuristic_skip （直接 none）
        #   触发 -> triage_source="llm"（此时本地用指纹分类器）
        # 我们接 LLM 时：仅启发式触发的那部分改走 LLM
        if r["triage_source"] == "llm" and llm_client is not None:
            candidates_for_llm.append(s)
        local_results[s.slice_id] = r

    if llm_client is None or not candidates_for_llm:
        return local_results

    # 第二步：对候选切片并发调用 LLM
    if verbose:
        print(f"   [llm-triage] {artifact.package}: "
              f"{len(candidates_for_llm)}/{len(slices)} slices -> LLM")

    def _worker(s: FunctionSlice) -> Dict:
        try:
            return _call_llm_triage_one(s, llm_client)
        except Exception as e:
            local = _local_heuristic_result(s)
            local["triage_source"] = "llm"
            local["json_error"] = True
            local["reason"] = f"llm_exception:{type(e).__name__}:{e}"
            return local

    results = parallel_map(_worker, candidates_for_llm, n_workers=n_workers)
    for s, r in zip(candidates_for_llm, results):
        local_results[s.slice_id] = r
    return local_results


def make_triage_fn(cache: Dict[str, Dict]) -> Callable[[FunctionSlice], Dict]:
    def _fn(s: FunctionSlice) -> Dict:
        return cache.get(s.slice_id) or _local_heuristic_result(s)
    return _fn


# ----------------------------------------------------------------------
# Deobfuscator：保持按 §4.5 内置工具链；LLM 不直接产出反混淆结果
# ----------------------------------------------------------------------

def llm_deob_fn(extract_dir, file_rel, ecosystem, obf_class, source):
    from .deobfuscator import deobfuscate_file
    from .utils import shannon_entropy
    before = {
        "entropy": shannon_entropy(source),
        "loc": len(source.splitlines()),
    }
    dr = deobfuscate_file(extract_dir, file_rel, ecosystem, obf_class, source)
    after = None
    if dr.success and dr.output_rel:
        new_path = os.path.join(extract_dir, dr.output_rel)
        try:
            with open(new_path, "r", encoding="utf-8") as f:
                new_src = f.read()
        except OSError:
            new_src = ""
        after = {
            "entropy": shannon_entropy(new_src),
            "loc": len(new_src.splitlines()),
        }
    return dr, before, after


# ----------------------------------------------------------------------
# §8.1 LLMJudge Prompt + 实装（§4.8）
# ----------------------------------------------------------------------

JUDGE_SYSTEM = (
    "你是一名供应链安全分析师，只根据给定的代码切片与上下文判定该切片是否为恶意代码。"
    "严格输出 JSON，不得输出任何其它文本。\n\n"
    "执行时机先验（entry_kind → 代码何时被执行）：\n"
    "- Level 0：npm_lifecycle / py_setup / py_pep517_hook / py_pth —— 安装时自动执行，恶意代码最高发位置\n"
    "- Level 1：npm_bin / py_sitecustomize —— 首次运行可执行文件 / 加载 site 时执行\n"
    "- Level 2：npm_main / py_init / py_entry_point —— import 触发执行\n"
    "- Level 3：npm_top_level / py_conftest —— 需要被显式导入或被 pytest 触发\n"
    "- Level 4：npm_other / py_other —— 仅被显式调用才执行\n\n"
    "Sink 类型先验（sink_kind → Sink 命中形态）：\n"
    "- static：通过规范名 module.attr 命中，确定性最高\n"
    "- dynamic：通过 obj[var](...) / getattr(obj,var)(...) 等动态属性访问命中，常用于绕过静态扫描\n"
    "- reflection：反射 API（getattr / __import__ / Reflect.apply / new Function(str) 等）本身即 Sink\n\n"
    "判决规则：Level 越低、sink_kind 越\"绕\"（dynamic > reflection > static），同等行为的"
    "恶意概率先验越高；但**先验不等于定罪**——合法的 setup.py 也可能合规地调用 subprocess 做本地构建。"
    "最终判决必须以切片内的实际行为证据（外联地址、凭据读取、持久化路径等）为准。"
)


JUDGE_USER_TEMPLATE = """Ecosystem : {ecosystem}
Package   : {package}
File      : {file}
EntryKind : {entry_kind}
SinkKind  : {sink_kind}
Sink(s)   : {sink}
Obfuscated: {was_obfuscated} (tool={deob_tool}, obf_class={obf_class})
Reslice   : version={reslice_version}
Hints     : {hints}

--- IMPORTS ---
{imports}

--- FUNCTION ---
{source_code}

--- LOCAL CALLEES (1-hop, same file) ---
{callees_inline}

请判定该切片的行为意图，并按如下 JSON 严格返回（不得输出其它文本）：
{{
  "verdict": "malicious|suspicious|benign",
  "categories": ["reverse_shell","data_exfil","install_hook_abuse","typosquat_payload","credential_theft","persistence","other"],
  "evidence_lines": [{{"start": int, "end": int, "note": "..."}}],
  "confidence": float,
  "priors_considered": ["entry_kind","sink_kind","obf_class"]
}}"""


VALID_VERDICTS = {"malicious", "suspicious", "benign"}


# ----------------------------------------------------------------------
# Step 2：包级"最终仲裁" Prompt + 实现
#
# 动机：初步聚合规则是 "任一 malicious → 包 malicious；全 benign → 包 benign；
# 其余 → suspicious"。实测在 4equest-6.9.2 / @alfalab 这类样本上，切片级
# verdict 都挣扎在 suspicious 0.75，单看聚合出 suspicious，但把所有切片
# 证据合在一起整体判断时，LLM 能给出更明确的 malicious 或 benign。
#
# 做法：若初步包级 verdict 属于 "suspicious" 或 "malicious 但 confidence<0.6"，
# 触发一次 final arbitration：把 **所有切片** 的 (func_name, sink, verdict,
# categories, evidence) 摘要 + package.json 元信息喂给 LLM，让它做最终判定。
# ----------------------------------------------------------------------

ARBITRATION_SYSTEM = (
    "你是一名供应链安全分析师。以下是某个包的所有代码切片、初步判决和 package.json 元信息，"
    "请基于全局证据做出**最终**的包级判决。只要存在任一可信的恶意证据（安装期外联、凭据窃取、"
    "typosquat + 可疑脚本组合等），就判 malicious。单独看每条切片可能弱，但组合看可能是强证据。"
    "严格只输出一个 JSON 对象。"
)

ARBITRATION_USER_TEMPLATE = """Ecosystem : {ecosystem}
Package   : {package}
InitialVerdict : {initial_verdict} (conf={initial_conf})
PackageMeta :
{package_meta}

切片证据（共 {n_slices} 条，按置信度降序）：
{slice_evidence}

请综合判断，严格按如下 JSON 返回：
{{
  "verdict": "malicious|suspicious|benign",
  "confidence": float,
  "reason": "一句话总结最强证据",
  "categories": ["reverse_shell","data_exfil","install_hook_abuse","typosquat_payload","credential_theft","persistence","other"]
}}"""


def _build_arbitration_prompt(
    rec: PackageRecord,
    pass1_slices: List[FunctionSlice],
    pass2_slices: List[FunctionSlice],
    slice_results: List[Dict],
    initial_verdict: str,
    initial_conf: Optional[float],
) -> str:
    # 组装 package.json 元信息
    pkg_meta_lines: List[str] = []
    # 从 pass1 切片找 __npm_scripts__ / __package_name_check__ 这些合成切片
    for s in pass1_slices:
        if s.func_name in ("__npm_scripts__", "__package_name_check__"):
            pkg_meta_lines.append(f"-- from {s.func_name}:")
            for ln in s.source_code.splitlines()[:12]:
                pkg_meta_lines.append(f"   {ln}")
    if not pkg_meta_lines:
        pkg_meta_lines.append("(no package meta synthesized)")

    # 切片证据排序：按 confidence 降序，malicious 优先
    def _rank(item):
        s, r = item
        priority_map = {"malicious": 0, "suspicious": 1, "benign": 2}
        return (priority_map.get(r.get("verdict", "benign"), 3), -r.get("confidence", 0.0))

    picked_slices = pass2_slices if pass2_slices else pass1_slices
    # 用 _pick_slices_for_judge 一致的集合
    picked = _pick_slices_for_judge(pass1_slices, pass2_slices, max_slices=0)
    paired = list(zip(picked, slice_results)) if len(picked) == len(slice_results) else \
             list(zip(pass1_slices[:len(slice_results)], slice_results))
    paired.sort(key=_rank)

    evidence_lines: List[str] = []
    for i, (s, r) in enumerate(paired[:15], 1):
        verdict = r.get("verdict", "?")
        conf = r.get("confidence", 0.0)
        cats = ",".join(r.get("categories", [])[:3]) or "-"
        sinks = ",".join(s.sink[:3])
        # 切片源码前 4 行摘要
        src_head = " / ".join(s.source_code.splitlines()[:4])[:220]
        evidence_lines.append(
            f"[{i:>2}] verdict={verdict:<10s} conf={conf:.2f}  file={s.file}  func={s.func_name}  "
            f"sink={sinks}  cats=[{cats}]\n     src: {src_head!r}"
        )
    if len(paired) > 15:
        evidence_lines.append(f"     ... and {len(paired) - 15} more slices omitted ...")

    return ARBITRATION_USER_TEMPLATE.format(
        ecosystem=rec.ecosystem,
        package=rec.package,
        initial_verdict=initial_verdict,
        initial_conf=f"{initial_conf:.2f}" if initial_conf is not None else "-",
        package_meta="\n".join(pkg_meta_lines),
        n_slices=len(paired),
        slice_evidence="\n".join(evidence_lines),
    )


def _final_arbitration(
    rec: PackageRecord,
    pass1_slices: List[FunctionSlice],
    pass2_slices: List[FunctionSlice],
    slice_results: List[Dict],
    client: OpenRouterClient,
    verbose: bool = False,
) -> None:
    """若包级 verdict 模糊，再调一次 LLM 做整体裁决。

    触发条件：
      - verdict='suspicious'（最典型）
      - verdict='malicious' 且 confidence < 0.6（LLM 犹豫）
    """
    needs_arb = (
        rec.verdict == "suspicious"
        or (rec.verdict == "malicious" and (rec.confidence or 0) < 0.6)
    )
    if not needs_arb:
        return

    if verbose:
        print(f"   [arbitration] {rec.package}: initial={rec.verdict} conf={rec.confidence} -> re-judge")

    user_prompt = _build_arbitration_prompt(
        rec, pass1_slices, pass2_slices, slice_results,
        initial_verdict=rec.verdict or "suspicious",
        initial_conf=rec.confidence,
    )
    try:
        call = client.chat_json(ARBITRATION_SYSTEM, user_prompt)
    except Exception as e:
        rec.llm_judge_json_error += 1
        return

    # 累计到 judge token / latency
    rec.llm_judge_tokens_total += call.total_tokens or (call.prompt_tokens + call.completion_tokens)
    rec.llm_judge_elapsed_ms += call.latency_ms

    if not call.ok or call.parsed is None:
        rec.llm_judge_json_error += 1
        return

    p = call.parsed
    verdict = str(p.get("verdict", rec.verdict)).lower()
    if verdict not in VALID_VERDICTS:
        verdict = rec.verdict or "suspicious"
    try:
        conf = float(p.get("confidence", rec.confidence or 0.5))
    except (TypeError, ValueError):
        conf = rec.confidence or 0.5
    cats = p.get("categories") or []
    if not isinstance(cats, list):
        cats = []
    cats = [str(c) for c in cats][:6]

    # 只有仲裁给出 "更明确" 的结论才覆盖（避免把 benign 错改 malicious）
    # 策略：初次是 suspicious 时无条件采用；初次是 malicious 时只允许 malicious 或 suspicious
    if rec.verdict == "suspicious":
        rec.verdict = verdict
        rec.confidence = conf
        rec.llm_judge_categories = sorted(set(rec.llm_judge_categories + cats))
    elif rec.verdict == "malicious" and verdict in ("malicious", "suspicious"):
        rec.verdict = verdict
        rec.confidence = conf
        rec.llm_judge_categories = sorted(set(rec.llm_judge_categories + cats))
    # benign -> 不做二次仲裁（0-切片默认 benign 不应被误拉高）


def _build_judge_user_prompt(slice_obj: FunctionSlice) -> str:
    keep_keys = {
        "entropy", "max_line_len", "avg_id_len", "eval_count",
        "has_fingerprint", "large_encoded_literal",
        "short_body", "fallback_rule", "dynamic_probe", "dyn_receiver",
        "raw_payload", "heavily_obfuscated",
        # __npm_scripts__ 合成切片专用字段
        "npm_scripts_synth", "lifecycle_keys",
        "has_suspicious_shell_pattern", "suspicious_shell_hits",
        # __package_name_check__ 合成切片专用字段（改进 ①）
        "package_name_anomaly", "typosquat_score", "typosquat_target",
        "typosquat_distance", "version", "version_anomaly_score",
    }
    hints = {k: v for k, v in slice_obj.confidence_hint.items() if k in keep_keys}

    imports_txt = "\n".join(slice_obj.imports)[:1500]
    callees_txt = "\n".join(slice_obj.callees_inline)[:2500]

    return JUDGE_USER_TEMPLATE.format(
        ecosystem=slice_obj.ecosystem,
        package=slice_obj.package,
        file=slice_obj.file,
        entry_kind=slice_obj.entry_kind,
        sink_kind=slice_obj.sink_kind,
        sink=",".join(slice_obj.sink),
        was_obfuscated=slice_obj.was_obfuscated,
        deob_tool=slice_obj.deob_tool or "-",
        obf_class=slice_obj.obf_class,
        reslice_version=slice_obj.reslice_version,
        hints=json.dumps(hints, ensure_ascii=False),
        imports=_truncate(imports_txt, 1500),
        source_code=_truncate(slice_obj.source_code, 4500),
        callees_inline=_truncate(callees_txt, 2500),
    )


def _call_llm_judge_one(
    slice_obj: FunctionSlice,
    client: OpenRouterClient,
) -> Dict:
    """对单条切片调用 LLM 做恶意/良性研判。返回归一化结果 dict。"""
    user_prompt = _build_judge_user_prompt(slice_obj)
    call = client.chat_json(JUDGE_SYSTEM, user_prompt)

    if not call.ok or call.parsed is None:
        return {
            "verdict": "suspicious",
            "confidence": 0.0,
            "categories": [],
            "evidence_lines": [],
            "reason": f"llm_failed: {call.error or 'parse_error'}",
            "tokens": call.total_tokens or (call.prompt_tokens + call.completion_tokens),
            "latency_ms": call.latency_ms,
            "json_error": True,
        }

    p = call.parsed
    verdict = str(p.get("verdict", "suspicious")).lower()
    if verdict not in VALID_VERDICTS:
        verdict = "suspicious"
    try:
        conf = float(p.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    cats = p.get("categories") or []
    if not isinstance(cats, list):
        cats = []
    cats = [str(c) for c in cats]

    return {
        "verdict": verdict,
        "confidence": conf,
        "categories": cats,
        "evidence_lines": p.get("evidence_lines") or [],
        "reason": str(p.get("priors_considered") or []),
        "tokens": call.total_tokens or (call.prompt_tokens + call.completion_tokens),
        "latency_ms": call.latency_ms,
        "json_error": False,
    }


# ----------------------------------------------------------------------
# §3 "送审选择"：v1 优先、v1 失败回落 v0、pass2 新切片一并送审
# ----------------------------------------------------------------------

def _pick_slices_for_judge(
    pass1_slices: List[FunctionSlice],
    pass2_slices: List[FunctionSlice],
    max_slices: int,
) -> List[FunctionSlice]:
    """按 §3 规则挑选送审切片列表。

    对同一 `(package, file, func_name, sink_joined)` 元组：
      - 若存在 pass2 切片（reslice_version=1），优先取；
      - 若 pass2 切片的 hint.reslice_failed=True，则回落到对应 pass1；
      - 若 pass2 中有 parent_slice_id=None 的新增切片（反混淆暴露的新 Sink），也入池；
      - 若 pass1 切片没有对应 pass2，原样入池。

    `max_slices` 超限时，按以下优先级裁剪：
      entry_lv 低（入口高危）> obf_class != none > sink_kind != static > 切片更长
    """
    # 1) 构造 key -> pass2 切片索引
    pass2_by_key: Dict[tuple, FunctionSlice] = {}
    pass2_orphan: List[FunctionSlice] = []
    for s in pass2_slices:
        if s.parent_slice_id is None:
            pass2_orphan.append(s)
        else:
            key = (s.package, s.func_name, "|".join(sorted(s.sink)))
            pass2_by_key[key] = s

    # 2) pass1 每条，查是否被 pass2 覆盖
    picked: List[FunctionSlice] = []
    for s in pass1_slices:
        key = (s.package, s.func_name, "|".join(sorted(s.sink)))
        if key in pass2_by_key:
            p2 = pass2_by_key[key]
            if p2.confidence_hint.get("reslice_failed"):
                picked.append(s)      # §3 回落到 pass1
            else:
                picked.append(p2)     # 用 pass2
        else:
            picked.append(s)

    picked.extend(pass2_orphan)

    # 3) 限流：超过 max_slices 时按优先级裁剪
    if max_slices > 0 and len(picked) > max_slices:
        from .entry_point import ENTRY_LEVEL
        def _priority(s: FunctionSlice) -> tuple:
            entry_lv = ENTRY_LEVEL.get(s.entry_kind, 9)
            obf_priority = 0 if s.obf_class == "none" else 1
            sink_priority = 0 if s.sink_kind == "static" else 1
            return (entry_lv, -obf_priority, -sink_priority, -len(s.source_code))
        picked.sort(key=_priority)
        picked = picked[:max_slices]

    return picked


# ----------------------------------------------------------------------
# 包级聚合：切片级 verdict → 包级 verdict（§4.8）
# ----------------------------------------------------------------------

def _aggregate_verdicts(slice_verdicts: List[Dict]) -> tuple:
    """返回 (package_verdict, package_confidence, category_union)。

    规则（§4.8）：
      - 任一切片 malicious → 包 malicious
      - 全部 benign → 包 benign
      - 其余 → 包 suspicious
    confidence = 对应 verdict 类别里最大 confidence
    """
    if not slice_verdicts:
        return ("benign", 0.0, [])

    any_malicious = [v for v in slice_verdicts if v["verdict"] == "malicious"]
    all_benign = all(v["verdict"] == "benign" for v in slice_verdicts)

    if any_malicious:
        max_conf = max(v["confidence"] for v in any_malicious)
        cats = sorted({c for v in any_malicious for c in v.get("categories", [])})
        return ("malicious", max_conf, cats)
    if all_benign:
        max_conf = max(v["confidence"] for v in slice_verdicts)
        return ("benign", max_conf, [])
    # suspicious
    susp = [v for v in slice_verdicts if v["verdict"] == "suspicious"]
    max_conf = max((v["confidence"] for v in susp), default=0.0)
    cats = sorted({c for v in susp for c in v.get("categories", [])})
    return ("suspicious", max_conf, cats)


# ----------------------------------------------------------------------
# 对外入口：对一包做 LLM Judge（可能跳过）
# ----------------------------------------------------------------------

def llm_judge_package(
    rec: PackageRecord,
    pass1_slices: List[FunctionSlice],
    pass2_slices: List[FunctionSlice],
    client: Optional[OpenRouterClient] = None,
    n_workers: int = 4,
    max_slices: int = 30,
    verbose: bool = False,
    enable_arbitration: bool = True,
) -> None:
    """执行或跳过 LLM Judge；结果写入 rec.verdict / confidence / llm_judge_*。

    enable_arbitration=True 时，对模糊结果（suspicious 或 malicious<0.6）再做一次
    包级最终仲裁（Step 2）。
    """
    if client is None:
        rec.verdict = None
        rec.confidence = None
        rec.llm_judge_elapsed_ms = 0.0
        rec.llm_judge_tokens_total = 0
        rec.llm_judge_json_error = 0
        rec.llm_judge_categories = []
        return

    picked = _pick_slices_for_judge(pass1_slices, pass2_slices, max_slices=max_slices)
    if not picked:
        # 没有切片：区分生态与情境给出更合理的默认 verdict。
        #   - npm：typosquat 恶意包经常被识别为"pass1_count=0"（正常代码 + 恶意 scripts 已合成
        #     __npm_scripts__ 切片；若还 0 切片说明 package.json 里也无可疑 lifecycle），
        #     默认 **suspicious** 比 benign 更诚实（"无证据" ≠ "清白"）
        #   - pypi：简单纯库也常没有 Sink 命中，默认 benign 与经验相符
        if rec.ecosystem == "npm":
            rec.verdict = "suspicious"
            rec.confidence = 0.5
            rec.llm_judge_categories = ["no_evidence"]
        else:
            rec.verdict = "benign"
            rec.confidence = 0.5
            rec.llm_judge_categories = []
        rec.llm_judge_elapsed_ms = 0.0
        rec.llm_judge_tokens_total = 0
        rec.llm_judge_json_error = 0
        return

    if verbose:
        print(f"   [llm-judge]  {rec.package}: {len(picked)} slices -> LLM "
              f"(pass1={len(pass1_slices)}, pass2={len(pass2_slices)})")

    def _worker(s: FunctionSlice) -> Dict:
        try:
            return _call_llm_judge_one(s, client)
        except Exception as e:
            return {
                "verdict": "suspicious",
                "confidence": 0.0,
                "categories": [],
                "evidence_lines": [],
                "tokens": 0, "latency_ms": 0.0,
                "json_error": True,
                "reason": f"exception:{type(e).__name__}:{e}",
            }

    t0 = time.perf_counter()
    results = parallel_map(_worker, picked, n_workers=n_workers)
    elapsed = (time.perf_counter() - t0) * 1000

    verdict, confidence, cats = _aggregate_verdicts(results)
    rec.verdict = verdict
    rec.confidence = confidence
    rec.llm_judge_elapsed_ms = elapsed
    rec.llm_judge_tokens_total = sum(int(r.get("tokens", 0) or 0) for r in results)
    rec.llm_judge_json_error = sum(1 for r in results if r.get("json_error"))
    rec.llm_judge_categories = cats

    # Step 2：对模糊结果（suspicious / 低置信 malicious）做一次整体仲裁
    if enable_arbitration:
        _final_arbitration(
            rec=rec,
            pass1_slices=pass1_slices,
            pass2_slices=pass2_slices,
            slice_results=results,
            client=client,
            verbose=verbose,
        )


# ----------------------------------------------------------------------
# Phase 2 主流程
# ----------------------------------------------------------------------

def _run_one_ecosystem(
    ecosystem: str,
    in_root: str,
    out_root: str,
    sensitive_csv: str,
    limit: int,
    truncate: bool,
    verbose: bool,
    llm_client: Optional[OpenRouterClient],
    llm_jobs: int,
    judge_enabled: bool = False,
    judge_max_slices: int = 30,
    enable_arbitration: bool = True,
) -> Dict:
    per_package_in = os.path.join(in_root, "per_package.jsonl")
    if not os.path.isfile(per_package_in):
        print(f"[skip] {per_package_in} 不存在，请先跑 Phase 1")
        return {"processed": 0, "failed": 0, "seconds": 0.0}

    os.makedirs(out_root, exist_ok=True)
    slices_v1_path = os.path.join(out_root, "slices_v1.jsonl")
    per_package_out = os.path.join(out_root, "per_package_phase2.jsonl")
    summary_path = os.path.join(out_root, "phase2_summary.json")
    if truncate:
        for p in (slices_v1_path, per_package_out, summary_path):
            if os.path.isfile(p):
                os.remove(p)

    workdir = os.path.join(in_root, "workdir")
    os.makedirs(workdir, exist_ok=True)

    t_start = time.perf_counter()
    recs_in = load_records(per_package_in)
    if limit:
        recs_in = recs_in[:limit]

    processed = 0
    failed = 0
    total_pkgs = len(recs_in)
    for idx, rec in enumerate(recs_in, 1):
        t_pkg_start = time.perf_counter()
        # 包开始前先 print 一行进度，避免"卡在某大包几分钟没输出"的错觉
        if verbose:
            elapsed_so_far = time.perf_counter() - t_start
            if processed > 0:
                avg_per_pkg = elapsed_so_far / processed
                eta_s = avg_per_pkg * (total_pkgs - idx + 1)
                eta_str = f"ETA={eta_s/60:.1f}min"
            else:
                eta_str = "ETA=?"
            print(f"\n>>> [{idx}/{total_pkgs}] {rec.package}  (已用 {elapsed_so_far/60:.1f}min, {eta_str})", flush=True)

        try:
            # 重新解压/切片，保证 Phase 2 的 extract_dir 与 entry_map 就位
            artifact: Pass1Artifact = pass1_only(
                tarball=rec.tarball,
                ecosystem=rec.ecosystem,
                workdir=workdir,
                package_name=rec.package,
                sensitive_csv=sensitive_csv,
            )

            # === Triage：预计算（必要时并发调 LLM），再注入 pass2_flow ===
            triage_cache = make_triage_cache_for_artifact(
                artifact=artifact,
                llm_client=llm_client,
                n_workers=llm_jobs,
                verbose=verbose,
            )
            triage_fn = make_triage_fn(triage_cache)

            pass2_slices, metrics = pass2_flow(
                artifact,
                triage_fn=triage_fn,
                deob_fn=llm_deob_fn,
            )

            # 补充 triage 的 LLM 延迟（pass2_flow 内的 triage_elapsed_ms 只算了
            # triage_fn 本地查表时间；真实 LLM 延迟累加在此处）
            llm_latency_total = sum(
                float(triage_cache[k].get("latency_ms", 0.0))
                for k in triage_cache
            )
            metrics.triage_elapsed_ms += llm_latency_total

            # 追加 pass2 切片
            with open(slices_v1_path, "a", encoding="utf-8") as f:
                for s in pass2_slices:
                    f.write(s.to_json() + "\n")

            # 补全 Triage / Deob / Pass2 指标
            merge_pass2_metrics(rec, metrics, artifact.result)

            # === LLM Judge（§4.8）：pass2 完成后立即对本包做包级定性 ===
            judge_client = llm_client if judge_enabled else None
            llm_judge_package(
                rec=rec,
                pass1_slices=artifact.pass1_slices,
                pass2_slices=pass2_slices,
                client=judge_client,
                n_workers=llm_jobs,
                max_slices=judge_max_slices,
                verbose=verbose,
                enable_arbitration=enable_arbitration,
            )
            append_record(per_package_out, rec)

            processed += 1
            if verbose:
                verdict_str = rec.verdict if rec.verdict else "N/A"
                conf_str = f"{rec.confidence:.2f}" if rec.confidence is not None else "-"
                pkg_elapsed = time.perf_counter() - t_pkg_start
                print(f"<<< [{idx}/{total_pkgs}] {rec.package}  "
                      f"[{pkg_elapsed:.1f}s]  "
                      f"triage={metrics.triage_total} "
                      f"sent_llm={metrics.triage_sent_to_llm} "
                      f"json_err={metrics.triage_json_error} "
                      f"tokens={metrics.triage_tokens_total} "
                      f"deob_ok={metrics.deob_success}/{metrics.deob_attempted} "
                      f"pass2={metrics.pass2_slice_count} "
                      f"verdict={verdict_str} conf={conf_str} "
                      f"judge_tok={rec.llm_judge_tokens_total}", flush=True)
        except Exception as e:
            failed += 1
            if verbose:
                traceback.print_exc()
            rec.errors.append(f"phase2_failed: {type(e).__name__}: {e}")
            append_record(per_package_out, rec)
            pkg_elapsed = time.perf_counter() - t_pkg_start
            if verbose:
                print(f"<<< [{idx}/{total_pkgs}] {rec.package}  [{pkg_elapsed:.1f}s]  "
                      f"FAILED: {type(e).__name__}: {e}", flush=True)

    elapsed = time.perf_counter() - t_start
    all_out_recs = load_records(per_package_out)
    summary = summarize_phase2(all_out_recs)
    summary["ecosystem"] = ecosystem
    summary["wall_clock_seconds"] = elapsed
    summary["processed_in_this_run"] = processed
    summary["failed_in_this_run"] = failed
    summary["llm_mode"] = bool(llm_client)
    summary["llm_model"] = llm_client.cfg.model if llm_client else None
    write_summary(summary_path, summary)
    return {"processed": processed, "failed": failed, "seconds": elapsed}


# ----------------------------------------------------------------------
# merge_pass2_metrics 需要把 triage_tokens_total / json_error 传进来；
# 我们之前已在 pass2_flow 把这些字段放进了 Pass2Metrics，所以自然可用
# ----------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phase2",
        description="Phase 2：Triage + Deob + Pass2；可选 LLM 模式（OpenRouter）",
    )
    p.add_argument("--ecosystem", choices=["npm", "pypi", "both"], default="both")
    p.add_argument("--in-npm", default="/home/lyx/code/data_npm")
    p.add_argument("--in-pypi", default="/home/lyx/code/data_pypi")
    p.add_argument("--out-npm", default="/home/lyx/code/data_npm")
    p.add_argument("--out-pypi", default="/home/lyx/code/data_pypi")
    p.add_argument("--sensitive-csv", default=DEFAULT_SENSITIVE_CSV)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--truncate", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")

    # LLM 相关
    p.add_argument("--llm-model", default=None,
                   help="OpenRouter 模型 id（如 deepseek/deepseek-chat-v3.1）。"
                        "不提供则走启发式占位（本地、0 token）")
    p.add_argument("--llm-jobs", type=int, default=4,
                   help="LLM 调用线程数（默认 4）")
    p.add_argument("--llm-max-tokens", type=int, default=512,
                   help="LLM 响应最大 token 数（默认 512）")
    p.add_argument("--llm-timeout", type=float, default=60.0)

    # LLM Judge（§4.8）
    p.add_argument("--llm-judge", action="store_true",
                   help="pass2 完成后立即调用 LLM 做包级定性判断（malicious/suspicious/benign）。"
                        "需与 --llm-model 配合使用")
    p.add_argument("--llm-judge-max-slices", type=int, default=30,
                   help="单包送审最多多少条切片（默认 30）。超出按 entry_lv / obf / sink_kind / 长度优先级裁剪")
    p.add_argument("--no-arbitration", action="store_true",
                   help="关闭 Step 2 的包级最终仲裁（默认 on；仅在调试时关闭）")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    llm_client: Optional[OpenRouterClient] = None
    if args.llm_model:
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            print("[fatal] 指定了 --llm-model 但 OPENROUTER_API_KEY 未设置", file=sys.stderr)
            return 2
        try:
            llm_client = build_client_from_env(
                model=args.llm_model,
                max_tokens=args.llm_max_tokens,
                timeout_s=args.llm_timeout,
            )
            print(f"[info] LLM 模式启用：model={args.llm_model} jobs={args.llm_jobs}")
        except Exception as e:
            print(f"[fatal] LLM 客户端初始化失败：{e}", file=sys.stderr)
            return 2
    else:
        print("[info] 未指定 --llm-model，走启发式 + 指纹占位（不消耗 token）")

    judge_enabled = bool(args.llm_judge and llm_client)
    if args.llm_judge and not llm_client:
        print("[warn] --llm-judge 已开启但未配置 --llm-model；Judge 将跳过")

    t_all = time.perf_counter()
    agg: Dict[str, Dict] = {}
    if args.ecosystem in ("npm", "both"):
        print(f"\n=== Phase 2: npm  in={args.in_npm}  out={args.out_npm} ===")
        agg["npm"] = _run_one_ecosystem(
            "npm", args.in_npm, args.out_npm, args.sensitive_csv,
            args.limit, args.truncate, args.verbose,
            llm_client, args.llm_jobs,
            judge_enabled=judge_enabled,
            judge_max_slices=args.llm_judge_max_slices,
            enable_arbitration=not args.no_arbitration,
        )
    if args.ecosystem in ("pypi", "both"):
        print(f"\n=== Phase 2: pypi  in={args.in_pypi}  out={args.out_pypi} ===")
        agg["pypi"] = _run_one_ecosystem(
            "pypi", args.in_pypi, args.out_pypi, args.sensitive_csv,
            args.limit, args.truncate, args.verbose,
            llm_client, args.llm_jobs,
            judge_enabled=judge_enabled,
            judge_max_slices=args.llm_judge_max_slices,
            enable_arbitration=not args.no_arbitration,
        )

    total_wall = time.perf_counter() - t_all
    print("\n=== Phase 2 DONE ===")
    print(json.dumps({
        "wall_clock_seconds": total_wall,
        "per_ecosystem": agg,
        "llm_mode": bool(llm_client),
        "llm_model": args.llm_model,
        "notes": {
            "llm_triage": ("REAL" if llm_client else "SKIPPED (heuristic placeholder)"),
            "llm_driven_deob": "SKIPPED (built-in tool chain by design §4.5)",
            "llm_judge": ("REAL" if judge_enabled else "SKIPPED (verdict=None)"),
        },
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
