"""OpenRouter API client with token usage tracking."""

import json
from pathlib import Path

import requests

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Model pricing: (input $/M tokens, output $/M tokens)
# Fetched from OpenRouter API at time of writing. Used for cost tracking only.
MODELS: dict[str, tuple[float, float]] = {
    # Budget
    "openai/gpt-5-nano": (0.050, 0.400),
    "qwen/qwen2.5-coder-7b-instruct": (0.030, 0.090),
    "qwen/qwen3-coder-30b-a3b-instruct": (0.070, 0.270),
    "mistralai/devstral-small": (0.100, 0.300),
    "meta-llama/llama-3.3-70b-instruct": (0.100, 0.320),
    "meta-llama/llama-4-maverick": (0.150, 0.600),
    # Mid
    "deepseek/deepseek-chat-v3-0324": (0.200, 0.770),
    "qwen/qwen3-coder": (0.220, 1.000),
    "openai/gpt-5-mini": (0.250, 2.000),
    "openai/gpt-5.1-codex-mini": (0.250, 2.000),
    "openai/gpt-5.2-codex": (1.750, 14.00),
    "deepseek/deepseek-v3.2": (0.260, 0.380),
    "mistralai/codestral-2508": (0.300, 0.900),
    "google/gemini-2.5-flash": (0.300, 2.500),
    "moonshotai/kimi-k2-0905": (0.400, 2.000),
    "minimax/minimax-m2.5": (0.500, 2.000),
    # Premium
    "openai/gpt-5.4-mini": (0.750, 4.500),
    "anthropic/claude-haiku-4.5": (1.000, 5.000),
    "openai/gpt-5": (1.250, 10.00),
    "google/gemini-2.5-pro": (1.250, 10.00),
    "google/gemini-3.1-pro-preview": (1.250, 10.00),
    "openai/gpt-4o": (2.500, 10.00),
    "anthropic/claude-sonnet-4": (3.000, 15.00),
    "anthropic/claude-sonnet-4.6": (3.000, 15.00),
    "anthropic/claude-opus-4.6": (5.000, 25.00),
}


def _fetch_model_pricing() -> dict[str, tuple[float, float]]:
    """Fetch current pricing from OpenRouter API. Returns {model_id: (in, out)}."""
    try:
        resp = requests.get("https://openrouter.ai/api/v1/models", timeout=10)
        resp.raise_for_status()
        return {
            m["id"]: (
                float(m["pricing"]["prompt"]) * 1_000_000,
                float(m["pricing"]["completion"]) * 1_000_000,
            )
            for m in resp.json().get("data", [])
            if float(m.get("pricing", {}).get("prompt", 0)) > 0
        }
    except Exception:
        return {}


def get_price(model: str) -> tuple[float, float]:
    """Get pricing for a model. Falls back to API lookup if not in MODELS dict."""
    if model in MODELS:
        return MODELS[model]
    # Try fetching live pricing (cached after first call)
    if not hasattr(get_price, "_live_cache"):
        get_price._live_cache = _fetch_model_pricing()
    if model in get_price._live_cache:
        price = get_price._live_cache[model]
        MODELS[model] = price  # cache for future calls
        return price
    return (0.0, 0.0)


def call(
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int = 4096,
    temperature: float = 0.0,
    timeout: int = 120,
) -> dict:
    """Send a chat completion request to OpenRouter. Returns raw API response."""
    resp = requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def extract_content(response: dict) -> str:
    """Extract the text content from an OpenRouter response."""
    if "choices" in response and response["choices"]:
        return response["choices"][0].get("message", {}).get("content", "")
    return ""


def extract_usage(response: dict) -> tuple[int, int]:
    """Extract (input_tokens, output_tokens) from an OpenRouter response."""
    usage = response.get("usage", {})
    return usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)


# ---- Token usage tracking ----


def load_usage(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_usage(usage: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(usage, indent=2))


def record_usage(
    usage: dict,
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> None:
    """Add tokens to the cumulative tracker for a model."""
    price = get_price(model)
    if model not in usage:
        usage[model] = {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
        }
    entry = usage[model]
    entry["calls"] += 1
    entry["input_tokens"] += input_tokens
    entry["output_tokens"] += output_tokens
    cost = (input_tokens * price[0] + output_tokens * price[1]) / 1_000_000
    entry["cost_usd"] = round(entry["cost_usd"] + cost, 6)


def usage_summary(usage: dict) -> str:
    """Return a formatted table of cumulative token usage."""
    lines = [f"{'Model':<45} {'Calls':>5} {'In':>10} {'Out':>10} {'Cost':>8}"]
    lines.append("-" * 82)
    total_cost = 0.0
    for model, stats in sorted(usage.items()):
        lines.append(
            f"{model:<45} {stats['calls']:>5} "
            f"{stats['input_tokens']:>10,} {stats['output_tokens']:>10,} "
            f"${stats['cost_usd']:>7.4f}"
        )
        total_cost += stats["cost_usd"]
    lines.append("-" * 82)
    lines.append(f"{'TOTAL':<45} {'':>5} {'':>10} {'':>10} ${total_cost:>7.4f}")
    return "\n".join(lines)


def call_and_track(
    api_key: str,
    model: str,
    prompt: str,
    usage: dict,
    **kwargs,
) -> tuple[str, int, int]:
    """Call OpenRouter and record token usage. Returns (content, tok_in, tok_out)."""
    response = call(api_key, model, prompt, **kwargs)
    content = extract_content(response)
    tok_in, tok_out = extract_usage(response)
    record_usage(usage, model, tok_in, tok_out)
    return content, tok_in, tok_out


def rebuild_usage_from_results(results_dir: Path) -> dict:
    """Recompute usage from all saved result JSONs. Fixes $0 cost entries."""
    usage: dict = {}
    for path in sorted(results_dir.rglob("*.json")):
        if path.name == "token_usage.json":
            continue
        try:
            d = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        model = d.get("model") or d.get("monitor_model") or d.get("judge_model")
        tok_in = d.get("input_tokens", 0)
        tok_out = d.get("output_tokens", 0)
        if model and (tok_in or tok_out):
            record_usage(usage, model, tok_in, tok_out)
    return usage
