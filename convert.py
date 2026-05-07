from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


def is_sft(rec: dict) -> bool:
    return "messages" in rec


def is_dpo(rec: dict) -> bool:
    return "chosen" in rec and "rejected" in rec


def to_alpaca(rec: dict) -> dict:
    if is_sft(rec):
        msgs = rec["messages"]
        return {
            "instruction": msgs[1]["content"],
            "input": "",
            "output": msgs[2]["content"],
            "system": msgs[0]["content"],
            "metadata": rec.get("metadata", {}),
        }
    if is_dpo(rec):
        return {
            "instruction": rec["instruction"],
            "input": "",
            "output": rec["chosen"],   # chosen is the canonical answer
            "metadata": rec.get("metadata", {}),
        }
    raise ValueError("Unrecognized record format")


def to_chatml(rec: dict) -> str:
    if not is_sft(rec):
        raise ValueError("ChatML conversion requires SFT format")
    parts = []
    for m in rec["messages"]:
        parts.append(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>")
    return "\n".join(parts)


def to_openai(rec: dict) -> dict:
    if is_sft(rec):
        return {"messages": rec["messages"]}
    if is_dpo(rec):
        
        return {"messages": [
            {"role": "user",      "content": rec["instruction"]},
            {"role": "assistant", "content": rec["chosen"]},
        ]}
    raise ValueError("Unrecognized record format")


def to_preference(rec: dict) -> dict:
    if is_dpo(rec):
        return {
            "prompt": rec["instruction"],
            "chosen": rec["chosen"],
            "rejected": rec["rejected"],
            "metadata": rec.get("metadata", {}),
        }
    raise ValueError("Preference format requires DPO records (with chosen + rejected)")


CONVERTERS = {
    "sharegpt":   lambda r: r,                       # passthrough
    "alpaca":     to_alpaca,
    "openai":     to_openai,
    "preference": to_preference,
}

def report_stats(rows: list[dict]) -> None:
    if not rows:
        print("(empty)"); return

    fmt = "SFT" if is_sft(rows[0]) else "DPO"
    print(f"\nFormat:   {fmt}")
    print(f"Records:  {len(rows)}")

    cwe = Counter(r.get("metadata", {}).get("cwe_id", "?") for r in rows)
    para = Counter(r.get("metadata", {}).get("paradigm", "?") for r in rows)
    level = Counter(r.get("metadata", {}).get("complexity_level", "?") for r in rows)
    label = Counter(r.get("metadata", {}).get("ground_truth_label", "?") for r in rows)
    domain = Counter(r.get("metadata", {}).get("domain", "?") for r in rows)

    if label:
        n0, n1 = label.get(0, 0), label.get(1, 0)
        print(f"Label:    safe={n0}  vuln={n1}  ({100*n1/(n0+n1):.0f}% vuln)")
    if level:
        print("Level:    " + "  ".join(f"{k}={v}" for k, v in sorted(level.items())))
    if para:
        print("Paradigm: " + "  ".join(f"{k}={v}" for k, v in sorted(para.items())))
    if cwe:
        print("CWE:")
        for k, v in sorted(cwe.items()):
            print(f"  {k:10s} {v}")
    if domain:
        print(f"Domains:  {len(domain)} unique  (top 3: "
              + ", ".join(f"{d}={n}" for d, n in domain.most_common(3)) + ")")

    total_chars = sum(
        sum(len(m["content"]) for m in r.get("messages", [])) if is_sft(r)
        else len(r.get("instruction", "")) + len(r.get("chosen", "")) + len(r.get("rejected", ""))
        for r in rows
    )
    print(f"Avg chars: {total_chars // len(rows)}")


def peek(rows: list[dict], n: int) -> None:
    for i, r in enumerate(rows[:n]):
        print(f"\n=== Record {i} ===")
        if is_sft(r):
            for m in r["messages"]:
                print(f"--- {m['role']} ---")
                content = m["content"]
                print(content if len(content) < 800 else content[:800] + " ... [truncated]")
        elif is_dpo(r):
            for fld in ("instruction", "chosen", "rejected"):
                content = r.get(fld, "")
                print(f"--- {fld} ---")
                print(content if len(content) < 600 else content[:600] + " ... [truncated]")
        if r.get("metadata"):
            print("--- metadata ---")
            print(json.dumps(r["metadata"], ensure_ascii=False, indent=2))


def hf_push(in_dir: Path, repo: str, private: bool) -> None:
    """Build a DatasetDict from the canonical layout and push to the Hub."""
    try:
        from datasets import Dataset, DatasetDict  # type: ignore
    except ImportError:
        sys.exit("`datasets` not installed. Run: pip install datasets")

    splits = {
        "sft_train":     in_dir / "train" / "sft_train.jsonl",
        "sft_val":       in_dir / "validation" / "sft_val.jsonl",
        "sft_test":      in_dir / "test" / "sft_test.jsonl",
        "sft_val_gold":  in_dir / "benchmark" / "sft_val_gold.jsonl",
        "dpo_train":     in_dir / "train" / "dpo_train.jsonl",
        "dpo_val":       in_dir / "validation" / "dpo_val.jsonl",
        "dpo_test":      in_dir / "test" / "dpo_test.jsonl",
    }

    def _flatten(rec: dict) -> dict:
        flat = {}
        flat.update(rec.get("metadata", {}))
        for k, v in rec.items():
            if k == "metadata":
                continue
            flat[k] = v if not isinstance(v, (dict, list)) else json.dumps(v, ensure_ascii=False)
        return flat

    dd = {}
    for name, path in splits.items():
        if not path.exists():
            print(f"  skip (not found): {name}")
            continue
        rows = [_flatten(r) for r in read_jsonl(path)]
        dd[name] = Dataset.from_list(rows)
        print(f"  loaded {name}: {len(rows)} rows")

    if not dd:
        sys.exit("No splits found under " + str(in_dir))

    print(f"\nPushing to {repo} (private={private})…")
    DatasetDict(dd).push_to_hub(repo, private=private)
    print(f"Done — https://huggingface.co/datasets/{repo}")


def main():
    p = argparse.ArgumentParser(
        description="Convert / inspect the C/C++ memory-safety dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[1] if "Examples:" in __doc__ else "",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--to", choices=["sharegpt", "alpaca", "chatml", "openai",
                                     "preference", "hf-push"],
                   help="Target format")
    g.add_argument("--stats", action="store_true",
                   help="Print distribution report on the input file")
    g.add_argument("--peek", type=int, metavar="N",
                   help="Print the first N records human-readably")
    p.add_argument("--in", dest="inp", required=True,
                   help="Input JSONL file (or directory for --to hf-push)")
    p.add_argument("--out",
                   help="Output file (required unless --stats/--peek/--to hf-push)")
    p.add_argument("--hf-repo", help="HuggingFace repo (e.g. user/dataset)")
    p.add_argument("--hf-private", action="store_true", help="Push as private repo")
    args = p.parse_args()

    inp = Path(args.inp)

    if args.stats:
        report_stats(read_jsonl(inp))
        return

    if args.peek is not None:
        peek(read_jsonl(inp), args.peek)
        return

    if args.to == "hf-push":
        if not args.hf_repo:
            p.error("--hf-push requires --hf-repo user/dataset")
        if not inp.is_dir():
            p.error("--hf-push expects --in to be a directory (e.g. ./data)")
        hf_push(inp, args.hf_repo, args.hf_private)
        return

    if not args.out:
        p.error(f"--to {args.to} requires --out <path>")
    out = Path(args.out)

    rows = read_jsonl(inp)

    if args.to == "chatml":
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(to_chatml(r) + "\n\n")
        print(f"Wrote {len(rows)} ChatML records → {out}")
        return

    converter = CONVERTERS[args.to]
    converted = [converter(r) for r in rows]
    n = write_jsonl(out, converted)
    print(f"Converted {n} records: {args.to} → {out}")


if __name__ == "__main__":
    main()
