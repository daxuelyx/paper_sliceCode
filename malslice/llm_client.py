"""OpenRouter HTTP 客户端（OpenAI 兼容）+ 并发工具。

- 读取 `OPENROUTER_API_KEY`、可选 `OPENROUTER_REFERER` / `OPENROUTER_APP_NAME`
- 严格 JSON 解析；失败时 1 次低温重试（§4.8 兜底规范）
- 记录 prompt_tokens / completion_tokens / latency_ms / json_error 供指标聚合
- `parallel_map`：简单线程池批量执行（OpenRouter 典型速率 ~10-30 RPS，4-8 并发足够）

注意：LLM 调用不保证幂等，如需回放请由调用方把 (prompt, response) 日志落盘。
"""
from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar

try:
    import requests  # type: ignore
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error


T = TypeVar("T")


DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"


@dataclass
class LLMCallResult:
    """LLM 单次调用的完整记录。"""
    ok: bool
    raw_text: str = ""                    # 原始返回文本（调试用）
    parsed: Optional[Dict] = None         # 解析后的 JSON
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    json_error: bool = False              # JSON 解析失败且无法修复
    http_status: int = 0
    error: str = ""
    retries: int = 0


@dataclass
class LLMClientConfig:
    api_key: str
    model: str
    endpoint: str = DEFAULT_ENDPOINT
    max_tokens: int = 512
    temperature: float = 0.0
    timeout_s: float = 60.0
    referer: str = ""                     # 某些 model 要求（非必需）
    app_name: str = "malslice"


class OpenRouterClient:
    """OpenAI 兼容的 HTTP 客户端，面向 chat/completions。"""

    def __init__(self, cfg: LLMClientConfig):
        if not cfg.api_key:
            raise ValueError("OpenRouter API key 为空，请设置环境变量 OPENROUTER_API_KEY")
        self.cfg = cfg

    # ------------------------------------------------------------------
    # 核心：严格 JSON Chat 调用（含 1 次低温重试）
    # ------------------------------------------------------------------

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        extra_schema_hint: Optional[str] = None,
    ) -> LLMCallResult:
        """调 chat completion；期望 LLM 返回纯 JSON。

        解析规则：
          1) 首先尝试直接 json.loads
          2) 失败时再尝试从 ```json ... ``` 代码块或第一对花括号间抽取
          3) 仍失败时以 temperature=0 重试 1 次，并在 user_prompt 追加
             "仅输出 JSON，不要任何解释文字"
        """
        # 第一次
        res = self._single_call(system_prompt, user_prompt, self.cfg.temperature)
        parsed = _best_effort_json(res.raw_text)
        if parsed is not None:
            res.parsed = parsed
            res.json_error = False
            return res

        # 重试：强制 temperature=0 + 收紧指令
        strict_user = user_prompt + "\n\n请严格只输出一个 JSON 对象，不要任何前后说明、不要 markdown 代码块。"
        res2 = self._single_call(system_prompt, strict_user, 0.0)
        res2.retries = res.retries + 1
        parsed2 = _best_effort_json(res2.raw_text)
        if parsed2 is not None:
            res2.parsed = parsed2
            res2.json_error = False
            return res2

        # 累计 token
        res2.prompt_tokens += res.prompt_tokens
        res2.completion_tokens += res.completion_tokens
        res2.total_tokens += res.total_tokens
        res2.latency_ms += res.latency_ms
        res2.json_error = True
        res2.ok = False
        return res2

    # ------------------------------------------------------------------

    def _single_call(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
    ) -> LLMCallResult:
        body = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": self.cfg.max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.cfg.api_key}",
            "Content-Type": "application/json",
        }
        if self.cfg.referer:
            headers["HTTP-Referer"] = self.cfg.referer
        if self.cfg.app_name:
            headers["X-Title"] = self.cfg.app_name

        t0 = time.perf_counter()
        try:
            if HAS_REQUESTS:
                resp = requests.post(
                    self.cfg.endpoint, headers=headers,
                    data=json.dumps(body), timeout=self.cfg.timeout_s,
                )
                status = resp.status_code
                text = resp.text
            else:
                req = urllib.request.Request(
                    self.cfg.endpoint, data=json.dumps(body).encode("utf-8"),
                    headers=headers, method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.cfg.timeout_s) as r:
                    status = r.status
                    text = r.read().decode("utf-8", errors="replace")
        except Exception as e:
            return LLMCallResult(
                ok=False, raw_text="", error=str(e),
                latency_ms=(time.perf_counter() - t0) * 1000,
            )

        latency = (time.perf_counter() - t0) * 1000

        if status >= 400:
            return LLMCallResult(
                ok=False, http_status=status, error=f"HTTP {status}: {text[:400]}",
                latency_ms=latency, raw_text=text,
            )

        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return LLMCallResult(
                ok=False, http_status=status, raw_text=text,
                error="response_not_json", latency_ms=latency,
            )

        content = ""
        try:
            content = obj["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return LLMCallResult(
                ok=False, http_status=status, raw_text=text,
                error="missing_choices", latency_ms=latency,
            )

        usage = obj.get("usage") or {}
        return LLMCallResult(
            ok=True,
            http_status=status,
            raw_text=content,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            total_tokens=int(usage.get("total_tokens") or 0),
            latency_ms=latency,
        )


# ----------------------------------------------------------------------
# JSON 抽取工具
# ----------------------------------------------------------------------

_MD_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
_FIRST_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _best_effort_json(text: str) -> Optional[Dict]:
    if not text:
        return None
    text = text.strip()
    # 1) 直接解析
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    # 2) 从 ```json ... ``` 代码块抽
    m = _MD_FENCE_RE.search(text)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    # 3) 抽第一段 { ... }
    m = _FIRST_OBJECT_RE.search(text)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    return None


# ----------------------------------------------------------------------
# 并发工具
# ----------------------------------------------------------------------

def parallel_map(
    fn: Callable[[T], Any],
    items: List[T],
    n_workers: int = 4,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> List[Any]:
    """把一批任务丢到线程池里执行。保持输入顺序。

    - fn: 接受单个 item，返回任意结果
    - progress_cb(done, total): 每完成一条回调一次（用于 tqdm/打印）
    """
    if n_workers <= 1 or len(items) <= 1:
        results = []
        for i, it in enumerate(items):
            results.append(fn(it))
            if progress_cb:
                progress_cb(i + 1, len(items))
        return results

    results: List[Any] = [None] * len(items)
    done_count = 0
    total = len(items)
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(fn, it): idx for idx, it in enumerate(items)}
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                results[idx] = fut.result()
            except Exception as e:
                results[idx] = e
            done_count += 1
            if progress_cb:
                progress_cb(done_count, total)
    return results


# ----------------------------------------------------------------------
# 工厂函数
# ----------------------------------------------------------------------

def build_client_from_env(
    model: str,
    endpoint: str = DEFAULT_ENDPOINT,
    max_tokens: int = 512,
    temperature: float = 0.0,
    timeout_s: float = 60.0,
) -> OpenRouterClient:
    cfg = LLMClientConfig(
        api_key=os.environ.get("OPENROUTER_API_KEY", ""),
        model=model,
        endpoint=os.environ.get("OPENROUTER_ENDPOINT", endpoint),
        max_tokens=max_tokens,
        temperature=temperature,
        timeout_s=timeout_s,
        referer=os.environ.get("OPENROUTER_REFERER", ""),
        app_name=os.environ.get("OPENROUTER_APP_NAME", "malslice"),
    )
    return OpenRouterClient(cfg)
