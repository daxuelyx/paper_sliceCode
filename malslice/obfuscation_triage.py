"""§4.4 ObfuscationTriage（启发式 + 指纹分类器）。

按用户要求跳过 LLM 调用：任何需要"LLM 定性"的切片在本实现中改由
「指纹分类器 + 启发式规则」给出 obf_class，后续 Deobfuscator 照常按 obf_class 路由。
字段语义（triage_source）：
  - heuristic_skip : 6 维启发式全不触发 -> obf_class=none，直接入池
  - llm            : 保留为指纹分类器结果（代表"本应送 LLM"的切片）
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .ir import FunctionSlice
from .utils import avg_identifier_length, max_line_length, shannon_entropy


JS_DYN_EXEC_RE = re.compile(
    r"\b(eval|Function|new\s+Function|setTimeout|setInterval|vm\.runIn|vm\.Script|vm\.compileFunction)\b"
)
PY_DYN_EXEC_RE = re.compile(
    r"\b(exec|eval|compile|marshal\.loads|__import__|importlib\.import_module)\s*\("
)

# 指纹：javascript-obfuscator 常见 _0x 数组头
JSOBF_STRINGARRAY_FP = re.compile(r"_0x[0-9a-f]{4,}")
JSOBF_STRINGARRAY_FP2 = re.compile(r"var\s+_0x\w+\s*=\s*\[")
JSFUCK_FP = re.compile(r"[\[\]\(\)\!\+]{200,}")  # jsfuck 几乎只用这几种字符
AAENCODE_FP = re.compile(r"ﾟωﾟﾉ|\(ﾟДﾟ\)")
WEBPACK_FP = re.compile(r"__webpack_require__|webpackChunk|webpackJsonp")

PYARMOR_FP = re.compile(r"__pyarmor__|pyarmor_runtime|from\s+pyarmor")
PYC_MARSHAL_FP = re.compile(r"marshal\.loads\s*\(|marshal\.load\s*\(")
PY_B64_CHAIN_FP = re.compile(
    r"(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode).*\)", re.DOTALL
)
PY_HEX_CHAIN_FP = re.compile(r"(?:exec|eval)\s*\(.*bytes\.fromhex\s*\(", re.DOTALL)
PY_ZLIB_CHAIN_FP = re.compile(r"(?:exec|eval)\s*\(.*zlib\.decompress\s*\(", re.DOTALL)

LARGE_BASE64_RE = re.compile(r"['\"][A-Za-z0-9+/=]{200,}['\"]")
LARGE_HEX_RE = re.compile(r"['\"](?:\\x[0-9a-fA-F]{2}){80,}['\"]|['\"][0-9a-fA-F]{200,}['\"]")


@dataclass
class TriageResult:
    obf_class: str
    confidence: float
    target_file_needed: bool
    triage_source: str   # 'heuristic_skip' | 'llm'
    reason: str
    hints: Dict


def _heuristic_check(text: str, ecosystem: str) -> Tuple[bool, Dict]:
    """返回 (any_triggered, hints_dict)。"""
    hints: Dict = {}
    triggered = False

    h = shannon_entropy(text)
    max_line = max_line_length(text)
    avg_id = avg_identifier_length(text)

    hints["entropy"] = round(h, 3)
    hints["max_line_len"] = max_line
    hints["avg_id_len"] = round(avg_id, 2)

    if ecosystem == "npm":
        if h > 4.8:
            triggered = True
        if max_line > 500:
            triggered = True
        if avg_id < 1.5:
            triggered = True
        eval_count = len(JS_DYN_EXEC_RE.findall(text))
        hints["eval_count"] = eval_count
        if eval_count >= 1:
            triggered = True
    else:
        if h > 4.6:
            triggered = True
        if max_line > 300:
            triggered = True
        if avg_id < 2.0:
            triggered = True
        eval_count = len(PY_DYN_EXEC_RE.findall(text))
        hints["eval_count"] = eval_count
        if eval_count >= 1:
            triggered = True

    # 大块编码字面量
    if LARGE_BASE64_RE.search(text) or LARGE_HEX_RE.search(text):
        hints["large_encoded_literal"] = True
        triggered = True

    return triggered, hints


def _fingerprint_class(text: str, ecosystem: str, hints: Dict) -> Optional[Tuple[str, float, bool, str]]:
    """指纹判型：命中则返回 (obf_class, confidence, target_file_needed, reason)。"""
    if ecosystem == "npm":
        if WEBPACK_FP.search(text):
            return ("webpack_bundle", 0.9, True, "webpack_require_fingerprint")
        if JSOBF_STRINGARRAY_FP2.search(text) or JSOBF_STRINGARRAY_FP.search(text):
            return ("jsobf_stringarray", 0.9, True, "_0x_string_array_fingerprint")
        if AAENCODE_FP.search(text):
            return ("aaencode", 0.95, False, "aaencode_kaomoji")
        if JSFUCK_FP.search(text):
            return ("jsfuck", 0.9, False, "jsfuck_chars")
        # eval_string: eval(atob(...)) / Function('...') / eval("...")
        if re.search(r"\beval\s*\(\s*atob\s*\(", text) or \
           re.search(r"\beval\s*\(\s*[\"'`]", text) or \
           re.search(r"\bFunction\s*\(\s*[\"'`]", text):
            return ("eval_string", 0.8, False, "eval_or_function_with_string")
    else:
        if PYARMOR_FP.search(text):
            return ("pyarmor", 0.95, True, "pyarmor_runtime_fingerprint")
        if PYC_MARSHAL_FP.search(text):
            return ("pyc_marshal", 0.9, True, "marshal_loads_fingerprint")
        if PY_B64_CHAIN_FP.search(text):
            return ("b64_chain", 0.9, False, "exec_base64_decode_chain")
        if PY_HEX_CHAIN_FP.search(text):
            return ("hex_chain", 0.9, False, "exec_bytes_fromhex_chain")
        if PY_ZLIB_CHAIN_FP.search(text):
            return ("zlib_chain", 0.9, False, "exec_zlib_decompress_chain")
    return None


def triage_slice(slice_obj: FunctionSlice, allow_llm: bool = False) -> TriageResult:
    """对单个切片做混淆定性。allow_llm 在本实现中无效（LLM 已跳过）。"""
    combined = slice_obj.source_code + "\n" + "\n".join(slice_obj.callees_inline)
    triggered, hints = _heuristic_check(combined, slice_obj.ecosystem)

    if not triggered:
        return TriageResult(
            obf_class="none",
            confidence=1.0,
            target_file_needed=False,
            triage_source="heuristic_skip",
            reason="all_six_heuristics_negative",
            hints=hints,
        )

    # 触发后：按指纹分类，落地到 12 选 1 的 obf_class
    fp = _fingerprint_class(combined, slice_obj.ecosystem, hints)
    if fp is not None:
        obf_class, conf, needs_file, reason = fp
        hints["has_fingerprint"] = obf_class
        return TriageResult(
            obf_class=obf_class,
            confidence=conf,
            target_file_needed=needs_file,
            triage_source="llm",  # 代表"本应送 LLM"的路径，此处由指纹兜底
            reason=f"fingerprint:{reason}",
            hints=hints,
        )

    # 启发式触发但指纹未命中 -> mixed_heavy（重度混淆兜底）
    return TriageResult(
        obf_class="mixed_heavy",
        confidence=0.6,
        target_file_needed=True,
        triage_source="llm",
        reason="heuristics_triggered_no_fingerprint",
        hints={**hints, "heavily_obfuscated": True},
    )


def apply_triage(slice_obj: FunctionSlice, result: TriageResult) -> None:
    """把 triage 结果写回 FunctionSlice（就地修改）。"""
    slice_obj.obf_class = result.obf_class
    slice_obj.obf_triage_confidence = result.confidence
    slice_obj.triage_source = result.triage_source
    slice_obj.confidence_hint.update(result.hints)
    slice_obj.confidence_hint["triage_reason"] = result.reason
    slice_obj.confidence_hint["target_file_needed"] = result.target_file_needed
