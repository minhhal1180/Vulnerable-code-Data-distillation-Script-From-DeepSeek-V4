# C/C++ Memory-Safety Dataset

A high-quality dataset for fine-tuning Large Language Models on **C/C++
memory-safety analysis**. Every record produces a structured 7-tag analysis
under one of five Chain-of-Thought reasoning paradigms.

- **2,393** SFT training records · **1,754** DPO training records
- 14 CWE classes (buffer overflows + pointer lifecycle)
- 5 reasoning paradigms (linear, tree-of-thoughts, counterfactual, reflexion, execution-trace)
- Stratified train / validation / test split + held-out OOD gold benchmark
- Qwen-safe (no special-token collisions), label-verified, no CWE-class leakage

---

## Quick start

```python
from datasets import load_dataset

ds = load_dataset("json", data_files={
    "train":      "data/train/sft_train.jsonl",
    "validation": "data/validation/sft_val.jsonl",
    "test":       "data/test/sft_test.jsonl",
    "gold":       "data/benchmark/sft_val_gold.jsonl",
})
```

The records use ShareGPT format and load directly into HuggingFace
`Trainer` / `SFTTrainer` / `DPOTrainer` without preprocessing.

---

## Repository layout

```
.
├── data/                       Final dataset (ShareGPT JSONL)
│   ├── DATASET_CARD.md
│   ├── train/{sft_train,dpo_train}.jsonl
│   ├── validation/{sft_val,dpo_val}.jsonl
│   ├── test/{sft_test,dpo_test}.jsonl
│   └── benchmark/sft_val_gold.jsonl     (held-out, fresh seed)
│
├── source/                     Original filtered corpora used during synthesis
│   ├── juliet/                 NIST Juliet test cases by CWE
│   ├── juliet_corpus.txt       de-tokenized + perplexity-filtered Juliet (175 MB)
│   └── diversevul_corpus.txt   de-tokenized + filtered DiverseVul (472 MB)
│
├── generate.py                 Synthesize new records via any DeepSeek-V4 API
├── convert.py                  Format conversion + HuggingFace push
├── requirements.txt
├── LICENSE
└── README.md
```

The `source/` corpora are large; if cloning via Git clean, fetch them with
[Git LFS](https://git-lfs.com/) or download separately. They are **not**
required to use the final dataset — only to regenerate / extend it.

---

## Format

Every SFT record is a ShareGPT chat:

```json
{
  "messages": [
    {"role": "system",    "content": "<paradigm-specific system prompt + 7-tag schema>"},
    {"role": "user",      "content": "Domain: ...\n<slice>{C/C++ code}</slice>"},
    {"role": "assistant", "content": "[SINK]: ...\n[CONCLUSION]: VULNERABLE CWE-XXX"}
  ],
  "metadata": {
    "snippet_id": "...", "cwe_id": "CWE-XXX",
    "complexity_level": "Level 2|3|4",
    "paradigm": "linear|tree_of_thoughts|counterfactual|reflexion|execution_trace",
    "ground_truth_label": 0|1,
    "domain": "..."
  }
}
```

Every DPO record is a preference triple:

```json
{
  "instruction": "Domain: ...\n<slice>...</slice>",
  "chosen":      "[SINK]: ...\n[CONCLUSION]: VULNERABLE CWE-XXX",
  "rejected":    "[SINK]: (subtle reasoning fallacy)\n[CONCLUSION]: NOT_VULNERABLE CWE-XXX",
  "metadata": {
    "fallacy_type": "...", "fallacy_method": "mechanical_perturbation",
    "snippet_id": "...", "ground_truth_label": 0|1
  }
}
```

The 7-tag schema is fixed:

```
[SINK]:        Dangerous function: <name> at line <X>.
[DESTINATION]: Buffer size calculation: Size_B = <bytes>.
[SOURCE]:      Input size tracing: Size_A is derived from <var>.
[CONSTRAINTS]: Guards found before sink: <code or 'none'>.
[SCRATCHPAD]:  <paradigm-specific multi-step reasoning>
[MATH]:        Required safety: Size_A <= Size_B; <HOLDS or VIOLATED>.
[CONCLUSION]:  <VULNERABLE or NOT_VULNERABLE> CWE-<ID>
```

See [`data/DATASET_CARD.md`](data/DATASET_CARD.md) for full distribution stats
and a recommended LoRA training config.

---

## Convert / inspect

```bash
# Distribution stats
python convert.py --stats --in data/train/sft_train.jsonl

# Peek at a record
python convert.py --peek 1 --in data/train/sft_train.jsonl

# Convert to other formats
python convert.py --to alpaca     --in data/train/sft_train.jsonl --out alpaca.jsonl
python convert.py --to chatml     --in data/train/sft_train.jsonl --out chatml.txt
python convert.py --to openai     --in data/train/sft_train.jsonl --out openai.jsonl
python convert.py --to preference --in data/train/dpo_train.jsonl --out pref.jsonl

# Push to HuggingFace Hub
python convert.py --to hf-push --in data/ --hf-repo your-name/cwe-memory-safety
```

---

## Generate (regenerate / extend)

`generate.py` is self-contained and works against any
DeepSeek-V4-compatible chat-completions endpoint (DeepSeek API,
self-hosted vLLM, OpenRouter, etc.).

```bash
# Set credentials in .env or export them
echo "DEEPSEEK_API_KEY=sk-..." > .env
# Optional overrides:
# DEEPSEEK_API_BASE=https://api.deepseek.com
# DEEPSEEK_MODEL_FLASH=deepseek-chat
# DEEPSEEK_MODEL_PRO=deepseek-reasoner

# Cheapest run: 200 SFT records, Flash only, $1 cap
python generate.py --sft 200 --budget 1.00 --out data_new

# Larger run with Pro thinking on hard paradigms + DPO
python generate.py --sft 3000 --dpo --pro --budget 5.00 --out data_new
```

Pipeline (per spec):

1. Synthesize a labeled C/C++ snippet with a `[TARGET_SINK]` marker.
2. Generate a 7-tag analysis under one of 5 reasoning paradigms.
3. Validate format + label agreement; auto-repair the conclusion if the
   model disagreed with the ground-truth label.
4. *(Optional)* Mechanically perturb the analysis to create a DPO pair
   (one of 9 reasoning fallacies inserted, conclusion flipped).

The CoT paradigm assignment is round-robin so all five paradigms appear
roughly equally — `linear` and `execution_trace` use the Flash tier;
`tree_of_thoughts`, `counterfactual`, `reflexion` use Pro when `--pro` is set.

---

## Quality guarantees

- 100 % records contain all 7 required tags
- 0 cross-split snippet-code overlap (train ↔ val/test/gold)
- 0 special-token collisions (`<|im_start|>`, `<|im_end|>`, `<|endoftext|>`, `<|fim_*|>`)
- 100 % `[CONCLUSION]` agreement with `ground_truth_label`
- DPO `chosen` ≠ `rejected` conclusion (label flip verified)
- No CWE-class hint in user prompts (model must derive CWE from code)
- CWE-prefixed function names (e.g. `CWE121_Stack_*`) renamed generically

---

## License

MIT. See [LICENSE](LICENSE).

The `source/juliet/` directory contains files derived from the
[NIST Juliet Test Suite](https://samate.nist.gov/SARD/test-suites/112)
(public domain). The `source/diversevul_corpus.txt` is derived from
[DiverseVul](https://github.com/wagner-group/diversevul) (MIT). The
synthetic and generated portions are released under MIT.
