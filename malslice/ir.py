"""§3 统一中间表示 FunctionSlice。"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


SinkKind = str  # 'static' | 'dynamic' | 'reflection'


@dataclass
class FunctionSlice:
    slice_id: str
    package: str
    ecosystem: str                    # 'npm' | 'pypi'
    file: str
    entry_kind: str
    sink: List[str]                   # 同函数多 Sink 合并为数组
    sink_kind: SinkKind
    func_name: str
    func_range: Tuple[int, int]
    source_code: str
    callees_inline: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    reslice_version: int = 0
    parent_slice_id: Optional[str] = None
    obf_class: str = "none"
    obf_triage_confidence: float = 1.0
    triage_source: str = "heuristic_skip"   # 'heuristic_skip' | 'llm'
    was_obfuscated: bool = False
    deob_tool: Optional[str] = None
    confidence_hint: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["func_range"] = list(self.func_range)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def compute_slice_id(package: str, file: str, func_name: str,
                     sinks: List[str], reslice_version: int) -> str:
    # 多 Sink 命中时 sink 数组要排序后再 hash，保证确定性
    sink_key = "|".join(sorted(sinks))
    raw = f"{package}|{file}|{func_name}|{sink_key}|{reslice_version}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()
