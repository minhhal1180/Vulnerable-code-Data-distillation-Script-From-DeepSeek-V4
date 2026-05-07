from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import random
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv(override=True)
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s | %(message)s")
log = logging.getLogger("generate")


TARGET_CWES = [119, 120, 121, 122, 125, 126, 127, 131, 415, 416, 476, 590, 680, 787]

CWE_DESCRIPTIONS = {
    119: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    120: "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
    121: "Stack-based Buffer Overflow",
    122: "Heap-based Buffer Overflow",
    125: "Out-of-bounds Read",
    126: "Buffer Over-read",
    127: "Buffer Under-read",
    131: "Incorrect Calculation of Buffer Size",
    415: "Double Free",
    416: "Use After Free",
    476: "NULL Pointer Dereference",
    590: "Free of Memory not on the Heap",
    680: "Integer Overflow to Buffer Overflow",
    787: "Out-of-bounds Write",
}

DOMAINS = [
    "Network Router", "Cryptographic Parser", "Image Codec", "Database Engine",
    "Web Server", "Game Engine", "Embedded Firmware", "Linux Kernel Module",
    "Compiler Front-end", "Filesystem Driver",
]

LEVELS = ["Level 2", "Level 3", "Level 4"]
LEVEL_DESCRIPTIONS = {
    "Level 2": "Intermediate — single-function with one guard or arithmetic step",
    "Level 3": "Advanced — multi-branch / loop with non-obvious bound dependency",
    "Level 4": "Expert — inter-procedural / aliased pointer / integer-promotion edge case",
}

PARADIGMS = ["linear", "tree_of_thoughts", "counterfactual", "reflexion", "execution_trace"]
PARADIGMS_HARD = {"tree_of_thoughts", "counterfactual", "reflexion"}  # benefit from Pro

# DeepSeek pricing — cents per 1M tokens (input, output).
PRICING = {
    "flash": {"input": 0.14, "output": 0.28},
    "pro":   {"input": 0.435, "output": 0.870},
}


PARADIGM_PROMPTS: dict[str, str] = {
    "linear": """You are a deterministic C/C++ static security analyzer using LINEAR reasoning.

MANDATORY [SCRATCHPAD] FORMAT:
Step 1) Define Size_A = [value from source]. Step 2) Define Size_B = [value from destination]. \
Step 3) Apply constraint: [state any if-check found before sink]. \
Step 4) Conclusion: [state whether Size_A can exceed Size_B on a straight-line path].

Rules:
- Trace ONE straight-line execution path only. No branching.
- In [CONSTRAINTS]: quote the exact guard code or write 'none'.
- In [MATH]: write the inequality: Size_A <= Size_B and state HOLDS or POTENTIALLY VIOLATED.""",

    "execution_trace": """You are a Symbolic Execution Engine tracing exact runtime values.

MANDATORY [SCRATCHPAD] FORMAT — create a state table:
| Iteration | Pointer/Index Value | Remaining Buffer | Status |
| 0         | [start value]       | [full size]      | OK     |
| N         | [value at N]        | [remaining]      | ...    |

Rules:
- Trace the pointer/index through EACH critical loop iteration.
- Show exact arithmetic: if buf[256], ptr starts at buf+0, after N writes ptr=buf+N.
- Show the exact step where pointer crosses buffer boundary (if vulnerable).
- In [MATH]: show the final boundary equation from your trace.""",

    "tree_of_thoughts": """You are a Path-Sensitive Code Analyzer. You MUST enumerate EVERY branch.

MANDATORY [SCRATCHPAD] FORMAT:
Path 1 (condition IS TRUE): [trace execution when guard condition is satisfied — what happens to Size_A vs Size_B?]
Path 2 (condition IS FALSE): [trace execution when guard condition is NOT satisfied — what happens?]
[If more branches exist, add Path 3, Path 4...]
Critical Path: [identify which path leads to violation, or state all paths are safe]

Rules:
- You MUST write the literal words 'Path 1' and 'Path 2' in your scratchpad.
- For EACH path: compute Size_A and Size_B explicitly.
- In [MATH]: specify WHICH path violates or satisfies Size_A <= Size_B.""",

    "counterfactual": """You are an expert Exploit Writer. ASSUME you are attacking this code.

MANDATORY [SCRATCHPAD] FORMAT:
Attacker Goal: [what memory region to corrupt / what pointer to hijack]
Malicious Input: [construct a SPECIFIC payload — exact value, size, or index that breaks the bound]
Bypass Analysis: [does the guard prevent your payload? show arithmetic: guard_check(N) = ? with your N]
Exploitation Path: [does Size_A = [your_value] exceed Size_B = [buffer_size]? by how many bytes?]

Rules:
- Begin SCRATCHPAD with 'Attacker Goal:' — this word is MANDATORY.
- Propose a CONCRETE numeric value for the malicious input (e.g., N=300 when buf=256).
- In [MATH]: use your attacker-chosen value to show the exact violation (or why it fails).""",

    "reflexion": """You are a Senior Security Auditor who catches your own mistakes.

MANDATORY [SCRATCHPAD] FORMAT:
Initial Assessment: [write a quick, possibly naive first reading of the vulnerability status]
HOWEVER, [explain what you missed — an edge case, integer wrap, sign extension, or alignment issue]
UPON CLOSER INSPECTION: [corrected analysis with exact values]
Final Reasoning: [conclude based on the corrected understanding]

Rules:
- You MUST write the words 'HOWEVER,' and 'UPON CLOSER INSPECTION:' in your scratchpad.
- The initial assessment should be plausible but incomplete.
- The correction should reveal a SPECIFIC hidden detail: integer overflow, unsigned/signed mismatch, \
sizeof(pointer) vs sizeof(type), struct padding, or off-by-one.
- In [MATH]: base your inequality ONLY on the corrected understanding, not the naive one.""",
}

SEVEN_TAG_SCHEMA = """
OUTPUT FORMAT — produce EXACTLY these 7 tags in order:

[SINK]: Dangerous function: <function_name> at line <X>.
[DESTINATION]: Buffer size calculation: Size_B = <exact_bytes_or_formula> for destination <var_name>.
[SOURCE]: Input size tracing: Size_A is derived from <source_var>. Source operand traced as <origin>.
[CONSTRAINTS]: Guards found before sink: <exact if-check code, or 'none'>
[SCRATCHPAD]: <Apply your assigned paradigm format exactly as specified above>
[MATH]: Required safety: Size_A <= Size_B; <state: HOLDS on all paths | POTENTIALLY VIOLATED on [which path]>
[CONCLUSION]: <VULNERABLE or NOT_VULNERABLE> CWE-<ID>"""

SFT_BASE_SYSTEM = (
    "You are a C/C++ static-analysis engine performing memory-boundary and pointer-lifecycle "
    "defect analysis. Architecture: x86_64 Linux LP64 (pointer/long=8B, int=4B, short=2B, char=1B).\n\n"
    "__PARADIGM__\n\n" + SEVEN_TAG_SCHEMA
)

SFT_USER_TMPL = """Perform 7-step defect analysis on this code fragment.

Domain:          {domain}

<slice>
{snippet}
</slice>

Instructions:
- Locate the line marked // [TARGET_SINK].
- Use [STRUCT_METADATA] byte values verbatim if present.
- LP64 word sizes: pointer/long=8B, int=4B, short=2B, char=1B.
- Conclude with VULNERABLE or NOT_VULNERABLE in [CONCLUSION].
- Output the 7 tags as raw text — no markdown fences, no JSON wrapping."""


SNIPPET_SYNTH_SYSTEM = """You synthesize realistic C/C++ snippets for security-analysis training.

REQUIREMENTS:
- Single self-contained function (15-50 lines).
- One clear sink line marked with the literal comment // [TARGET_SINK].
- If the function uses fixed-size arrays/structs, append a comment // [STRUCT_METADATA]: Size=N bytes
  on the same line as the declaration so the analyzer can use exact byte values.
- Include realistic helper context — domain-appropriate variable names, error-handling style, etc.
- DO NOT include any "// CWE-XXX" or "// VULNERABLE" hints — the analyzer must reason from code alone.
- Use idiomatic C/C++ for the requested domain (kernel uses kmalloc; STL uses std::vector; etc.).

Return JSON wrapped in a single ```json fenced block:
{
  "snippet":              "<C/C++ source with [TARGET_SINK] marker>",
  "sink_line_number":     <int — 1-based line within the snippet>,
  "destination_buffer":   "<destination var name>",
  "destination_size_bytes": "<exact bytes or formula>",
  "source_operand":       "<source var name or expression>",
  "guards_present":       "<exact guard code or 'none'>",
  "rationale":            "<one sentence — why this is or isn't vulnerable>"
}
"""

SNIPPET_USER_TMPL = """Synthesize a {label_word} snippet for the following spec:

CWE class:    CWE-{cwe} ({cwe_desc})
Complexity:   {level} — {level_desc}
Domain:       {domain}
Required label: {label_word} ({label_int})

If label is VULNERABLE (1): the snippet MUST contain a real reachable defect of this CWE class.
If label is SAFE       (0): the snippet MUST contain a guard / size-check / lifetime control that
                            PROVABLY prevents the defect — guards must be on every path.

Avoid trivial / textbook patterns. Aim for a realistic {domain}-style code shape."""


DPO_FALLACY_TYPES = {
    "loop bound off-by-one":    "change `i < N` to `i <= N` somewhere reasoning — flip safety",
    "size in elements vs bytes": "ignore element-size multiplier (e.g., wchar_t=4B) — wrong byte arithmetic",
    "unsigned underflow":        "claim `len - 1 >= 0` always — ignore underflow when len=0",
    "guard on wrong variable":   "claim a guard protects sink when guard checks unrelated var",
    "freed-pointer reuse":       "claim pointer is valid after free — ignore lifetime",
    "null after malloc":         "skip null-check after malloc — assume always non-null",
    "integer truncation":        "claim 32-bit value fits 16-bit — ignore truncation",
    "signed/unsigned compare":   "compare signed-to-unsigned — claim semantics match",
    "alias-pointer width":       "claim sizeof(ptr) is sizeof(target) — ignore pointer width",
}


@dataclass
class SnippetSpec:
    snippet_id: str
    cwe: int
    level: str
    label: int
    domain: str
    paradigm: str


@dataclass
class Snippet:
    snippet: str
    sink_line: int | None
    dest_buffer: str
    dest_bytes: str
    source_operand: str
    guards: str
    rationale: str


class APIClient:
    def __init__(self, api_key: str, base_url: str, max_concurrent: int = 16):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.sem = asyncio.Semaphore(max_concurrent)
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10, read=180, write=30, pool=10),
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
        )
        self.input_tokens = 0
        self.output_tokens = 0
        self.flash_input = 0
        self.flash_output = 0
        self.pro_input = 0
        self.pro_output = 0
        self.cost = 0.0

    async def __aenter__(self): return self

    async def __aexit__(self, *_):
        await self.client.aclose()

    async def chat(self, model: str, messages: list[dict], *,
                    is_pro: bool = False, max_tokens: int = 2048,
                    temperature: float = 0.7, retries: int = 3) -> str | None:
        url = self.base_url + "/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        for attempt in range(retries):
            async with self.sem:
                try:
                    r = await self.client.post(url, json=payload)
                    if r.status_code == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    r.raise_for_status()
                    data = r.json()
                except (httpx.HTTPError, json.JSONDecodeError) as e:
                    if attempt == retries - 1:
                        log.debug("API failed after %d retries: %s", retries, e)
                        return None
                    await asyncio.sleep(2 ** attempt)
                    continue
            choice = (data.get("choices") or [{}])[0]
            text = choice.get("message", {}).get("content")
            usage = data.get("usage", {})
            inp = usage.get("prompt_tokens", 0)
            out = usage.get("completion_tokens", 0)
            self.input_tokens += inp
            self.output_tokens += out
            tier_pricing = PRICING["pro"] if is_pro else PRICING["flash"]
            if is_pro:
                self.pro_input += inp; self.pro_output += out
            else:
                self.flash_input += inp; self.flash_output += out
            self.cost += inp * tier_pricing["input"] / 1_000_000
            self.cost += out * tier_pricing["output"] / 1_000_000
            return text
        return None


_FENCED_JSON_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)
_CONCLUSION_RE = re.compile(r"\[CONCLUSION\]\s*:\s*(VULNERABLE|NOT_VULNERABLE)\s+CWE-?(\d+)", re.I)
_TAGS = ["[SINK]", "[DESTINATION]", "[SOURCE]", "[CONSTRAINTS]",
         "[SCRATCHPAD]", "[MATH]", "[CONCLUSION]"]
_PARA_MARKERS: dict[str, list[str]] = {
    "tree_of_thoughts": ["Path 1", "Path 2", "path 1", "path 2"],
    "counterfactual":   ["Attacker Goal", "Malicious Input", "attacker", "malicious", "payload"],
    "reflexion":        ["HOWEVER,", "UPON CLOSER INSPECTION", "Initial Assessment"],
    "execution_trace":  ["Iteration", "iteration", "| 0 ", "Step 1)"],
    "linear":           ["Step 1)", "Step 2)", "Step 3)"],
}


def _parse_fenced_json(text: str) -> dict | None:
    if not text:
        return None
    m = _FENCED_JSON_RE.search(text)
    if not m:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


async def synthesize_snippet(client: APIClient, spec: SnippetSpec,
                              flash_model: str) -> Snippet | None:
    user = SNIPPET_USER_TMPL.format(
        cwe=spec.cwe,
        cwe_desc=CWE_DESCRIPTIONS.get(spec.cwe, "memory-safety class"),
        level=spec.level,
        level_desc=LEVEL_DESCRIPTIONS[spec.level],
        domain=spec.domain,
        label_word="VULNERABLE" if spec.label == 1 else "SAFE",
        label_int=spec.label,
    )
    messages = [
        {"role": "system", "content": SNIPPET_SYNTH_SYSTEM},
        {"role": "user", "content": user},
    ]
    text = await client.chat(flash_model, messages, is_pro=False, max_tokens=1500)
    data = _parse_fenced_json(text) if text else None
    if not data or not isinstance(data, dict):
        return None
    code = data.get("snippet") or ""
    if "[TARGET_SINK]" not in code:
        return None
    return Snippet(
        snippet=code.strip(),
        sink_line=data.get("sink_line_number"),
        dest_buffer=data.get("destination_buffer", ""),
        dest_bytes=str(data.get("destination_size_bytes", "")),
        source_operand=data.get("source_operand", ""),
        guards=data.get("guards_present", "none"),
        rationale=data.get("rationale", ""),
    )


def _quality_check(analysis: str, paradigm: str) -> str | None:
    if not all(t in analysis for t in _TAGS):
        return "missing_tag"
    sp = analysis.find("[SCRATCHPAD]")
    mt = analysis.find("[MATH]")
    if sp == -1 or mt == -1 or mt - sp < 100:
        return "scratchpad_too_short"
    sink = analysis[analysis.find("[SINK]"):analysis.find("[DESTINATION]")]
    if "No dangerous function" in sink or "Not applicable" in sink:
        return "no_sink"
    markers = _PARA_MARKERS.get(paradigm, [])
    if markers and not any(m in analysis[sp:mt] for m in markers):
        return "paradigm_marker_missing"
    return None


async def generate_sft(client: APIClient, snip: Snippet, spec: SnippetSpec,
                        flash_model: str, pro_model: str | None,
                        max_attempts: int = 2) -> dict | None:
    """Returns a ShareGPT record on success, or None."""
    use_pro = (spec.paradigm in PARADIGMS_HARD) and (pro_model is not None)
    model = pro_model if use_pro else flash_model

    system = SFT_BASE_SYSTEM.replace("__PARADIGM__", PARADIGM_PROMPTS[spec.paradigm])
    user = SFT_USER_TMPL.format(domain=spec.domain, snippet=snip.snippet)
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": user}]

    for _ in range(max_attempts):
        analysis = await client.chat(model, messages, is_pro=use_pro,
                                       max_tokens=2400, temperature=0.5)
        if not analysis:
            continue
        analysis = analysis.strip().lstrip("```").rstrip("```").strip()

        if _quality_check(analysis, spec.paradigm):
            continue

        m = _CONCLUSION_RE.search(analysis)
        if not m:
            continue
        verdict = m.group(1).upper()
        predicted_label = 1 if verdict == "VULNERABLE" else 0
        if predicted_label != spec.label:
            # Repair the conclusion to match ground truth — preserves reasoning,
            # ensures training signal is correct.
            new_verdict = "VULNERABLE" if spec.label == 1 else "NOT_VULNERABLE"
            new = f"[CONCLUSION]: {new_verdict} CWE-{m.group(2)}"
            analysis = analysis[:m.start()] + new + analysis[m.end():]

        return {
            "messages": [
                {"role": "system",    "content": system},
                {"role": "user",      "content": user},
                {"role": "assistant", "content": analysis},
            ],
            "metadata": {
                "snippet_id": spec.snippet_id,
                "cwe_id": f"CWE-{spec.cwe}",
                "complexity_level": spec.level,
                "paradigm": spec.paradigm,
                "ground_truth_label": spec.label,
                "domain": spec.domain,
                "label_repaired": predicted_label != spec.label,
                "tier": "pro" if use_pro else "flash",
            },
        }
    return None


# ── DPO mechanical perturbation ──────────────────────────────────────────────
def perturb_for_dpo(record: dict) -> dict | None:
    """Build a DPO triple from an SFT record by flipping the conclusion and
    inserting a subtle reasoning fallacy in the [SCRATCHPAD]."""
    asst = record["messages"][2]["content"]
    meta = record["metadata"]
    m = _CONCLUSION_RE.search(asst)
    if not m:
        return None

    # Flip the verdict for `rejected`
    new_verdict = "NOT_VULNERABLE" if m.group(1).upper() == "VULNERABLE" else "VULNERABLE"
    rejected_conclusion = f"[CONCLUSION]: {new_verdict} CWE-{m.group(2)}"

    # Inject one fallacy phrase at the start of [SCRATCHPAD] in the rejected version
    fallacy_type = random.choice(list(DPO_FALLACY_TYPES.keys()))
    fallacy_note = f"(NOTE: {DPO_FALLACY_TYPES[fallacy_type]}.) "
    sp = asst.find("[SCRATCHPAD]:")
    if sp == -1:
        return None
    rejected = (
        asst[: sp + len("[SCRATCHPAD]:")]
        + " "
        + fallacy_note
        + asst[sp + len("[SCRATCHPAD]:"):m.start()]
        + rejected_conclusion
        + asst[m.end():]
    )
    instruction = record["messages"][1]["content"]
    return {
        "instruction": instruction,
        "chosen": asst,
        "rejected": rejected,
        "metadata": {
            "snippet_id": meta["snippet_id"],
            "cwe_id": meta["cwe_id"],
            "complexity_level": meta["complexity_level"],
            "paradigm": meta["paradigm"],
            "ground_truth_label": meta["ground_truth_label"],
            "domain": meta["domain"],
            "fallacy_type": fallacy_type,
            "fallacy_method": "mechanical_perturbation",
            "dpo_source": "mechanical",
        },
    }


# ════════════════════════════════════════════════════════════════════════════
#  ORCHESTRATION
# ════════════════════════════════════════════════════════════════════════════
def _hid(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def build_plan(n_sft: int, seed: int) -> list[SnippetSpec]:
    """Round-robin CoT, balanced (CWE × label × level)."""
    rng = random.Random(seed)
    specs: list[SnippetSpec] = []
    levels_w = [("Level 2", 0.55), ("Level 3", 0.30), ("Level 4", 0.15)]
    levels_pop, levels_p = zip(*levels_w)

    for i in range(n_sft):
        cwe = TARGET_CWES[i % len(TARGET_CWES)]
        label = i % 2
        level = rng.choices(levels_pop, weights=levels_p)[0]
        domain = rng.choice(DOMAINS)
        paradigm = PARADIGMS[i % len(PARADIGMS)]
        sid = f"synth-{_hid(cwe, label, level, paradigm, i, seed)}"
        specs.append(SnippetSpec(sid, cwe, level, label, domain, paradigm))
    rng.shuffle(specs)
    return specs


class _State:
    def __init__(self):
        self.t0 = time.monotonic()
        self.sft_ok = 0
        self.sft_fail = 0
        self.dpo_ok = 0


async def _process_one(client: APIClient, spec: SnippetSpec,
                        flash_model: str, pro_model: str | None,
                        sft_writer, dpo_writer, want_dpo: bool,
                        state: _State) -> None:
    snip = await synthesize_snippet(client, spec, flash_model)
    if snip is None:
        state.sft_fail += 1
        return

    rec = await generate_sft(client, snip, spec, flash_model, pro_model)
    if rec is None:
        state.sft_fail += 1
        return

    state.sft_ok += 1
    sft_writer.write_line(rec)

    if want_dpo:
        dpo = perturb_for_dpo(rec)
        if dpo:
            state.dpo_ok += 1
            dpo_writer.write_line(dpo)


class _JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8", newline="\n")
        self._lock = asyncio.Lock()

    def write_line(self, obj: dict) -> None:
        self._fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self):
        self._fh.close()


async def _reporter(client: APIClient, state: _State, total: int,
                    budget_cap: float, interval: float = 15.0):
    while True:
        await asyncio.sleep(interval)
        elapsed = time.monotonic() - state.t0
        log.info("ok=%d fail=%d dpo=%d / %d  cost=$%.3f / $%.2f  %.1fm",
                 state.sft_ok, state.sft_fail, state.dpo_ok, total,
                 client.cost, budget_cap, elapsed / 60)
        if budget_cap > 0 and client.cost >= budget_cap:
            log.warning("BUDGET CAP $%.2f reached — stopping", budget_cap)
            os.kill(os.getpid(), 15)
            return


async def main_async(args):
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        log.error("DEEPSEEK_API_KEY not set (in env or .env)")
        sys.exit(1)
    base_url = os.environ.get("DEEPSEEK_API_BASE", "https://api.deepseek.com")
    flash_model = os.environ.get("DEEPSEEK_MODEL_FLASH", "deepseek-chat")
    pro_model = os.environ.get("DEEPSEEK_MODEL_PRO", "deepseek-reasoner") if args.pro else None

    log.info("Endpoint:    %s", base_url)
    log.info("Flash model: %s", flash_model)
    log.info("Pro model:   %s", pro_model or "(disabled — Flash only)")

    plan = build_plan(args.sft, args.seed)
    log.info("Plan: %d specs (CWE × paradigm × level balanced)", len(plan))

    out_dir = Path(args.out).resolve()
    sft_path = out_dir / "sft.jsonl"
    dpo_path = out_dir / "dpo.jsonl"
    sft_w = _JsonlWriter(sft_path)
    dpo_w = _JsonlWriter(dpo_path)

    state = _State()
    async with APIClient(api_key, base_url, max_concurrent=args.concurrency) as client:
        reporter = asyncio.create_task(_reporter(client, state, len(plan), args.budget))
        tasks = [
            asyncio.create_task(
                _process_one(client, spec, flash_model, pro_model, sft_w, dpo_w,
                             args.dpo, state)
            )
            for spec in plan
        ]
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except (KeyboardInterrupt, SystemExit):
            log.warning("Interrupted — flushing")
        finally:
            reporter.cancel()
            try: await reporter
            except asyncio.CancelledError: pass

    sft_w.close()
    dpo_w.close()

    elapsed = time.monotonic() - state.t0
    log.info("=" * 60)
    log.info(" DONE")
    log.info(" SFT:  %d records written → %s", state.sft_ok, sft_path)
    if args.dpo:
        log.info(" DPO:  %d records written → %s", state.dpo_ok, dpo_path)
    log.info(" Failed: %d", state.sft_fail)
    log.info(" Cost:   $%.3f  (Flash %d / %d tok; Pro %d / %d tok)",
             client.cost, client.flash_input, client.flash_output,
             client.pro_input, client.pro_output)
    log.info(" Time:   %.1fm", elapsed / 60)
    log.info("=" * 60)


def main():
    p = argparse.ArgumentParser(
        description="Generate a C/C++ memory-safety dataset via a DeepSeek-V4 API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Env vars: DEEPSEEK_API_KEY (required), DEEPSEEK_API_BASE, "
               "DEEPSEEK_MODEL_FLASH, DEEPSEEK_MODEL_PRO. .env is loaded if present.",
    )
    p.add_argument("--sft", type=int, default=200,
                   help="Number of SFT records to attempt (default 200)")
    p.add_argument("--dpo", action="store_true",
                   help="Also write a DPO file by mechanically perturbing each SFT record")
    p.add_argument("--pro", action="store_true",
                   help="Use the Pro/thinking model for hard paradigms "
                        "(tree_of_thoughts, counterfactual, reflexion). Costs ~3x more.")
    p.add_argument("--budget", type=float, default=2.00,
                   help="Hard USD budget cap; pipeline auto-terminates on reach (default $2)")
    p.add_argument("--concurrency", type=int, default=16,
                   help="Max in-flight API requests (default 16)")
    p.add_argument("--out", default="data_new",
                   help="Output directory (default ./data_new)")
    p.add_argument("--seed", type=int, default=1337,
                   help="Plan seed (use a different seed for held-out evaluation)")
    args = p.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
