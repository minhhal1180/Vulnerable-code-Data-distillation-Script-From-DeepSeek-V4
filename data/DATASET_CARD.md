# C/C++ Memory-Safety Dataset for Qwen 2.5 Coder 7B LoRA

## Files for training

| File | Records | Size | Purpose |
|---|---|---|---|
| `sft_train.jsonl` | **2414** | 20 MB | SFT training (85% split) |
| `sft_val.jsonl` | **285** | 2.3 MB | In-distribution eval during training |
| `sft_test.jsonl` | **140** | 1.2 MB | In-distribution held-out test |
| `sft_val_gold.jsonl` | **89** | 850 KB | **Out-of-distribution gold benchmark** (fresh API, seed=9999) |
| `dpo_train.jsonl` | **1812** | 7.0 MB | DPO training (85% split) |
| `dpo_val.jsonl` | **214** | 840 KB | In-distribution DPO eval |
| `dpo_test.jsonl` | **105** | 414 KB | In-distribution DPO held-out test |

### Backup / reference files
| File | Records | Purpose |
|---|---|---|
| `sft_train_shuffled.jsonl.full` | 2839 | Pre-split full SFT |
| `dpo_train_shuffled.jsonl.full` | 2131 | Pre-split full DPO |
| `sft_final.jsonl`, `dpo_final.jsonl` | — | Pre-validation raw |
| `rejected.jsonl` | — | Records dropped (with reasons) |

## Validation strategy — TWO-TIER

**1. In-distribution** (`sft_val.jsonl` + `sft_test.jsonl`):
   - Stratified 85/10/5 split from training data (seed=42)
   - Same distribution as train → use as `eval_dataset` in HuggingFace `Trainer`
   - Stratified by (CWE × label) → all 14 CWEs in each split

**2. Out-of-distribution gold** (`sft_val_gold.jsonl`):
   - 89 records generated with **fresh API** (seed=9999, ≠ train seed=1337)
   - Pro thinking model for hard paradigms (highest quality)
   - All 14 CWEs (5-10 each), 5 paradigms balanced
   - 71% hard tasks (Level 3-4), 72% vulnerable
   - **Use for final benchmark** — completely held-out, dedup-verified vs train

## Methodology — 5-CoT × 7-Step framework

- **5 reasoning paradigms**: linear, tree-of-thoughts, counterfactual, reflexion, execution-trace
- **7-tag analysis schema**: SINK, DESTINATION, SOURCE, CONSTRAINTS, SCRATCHPAD, MATH, CONCLUSION
- **4 complexity levels**: Foundational → Expert
- **Architecture**: x86_64 Linux LP64 (pointer/long=8B, int=4B, short=2B, char=1B)

## Quality guarantees (Qwen-safe)

- ✅ No `<|im_start|>`, `<|im_end|>`, `<|endoftext|>`, `<|fim_*|>` token collisions
- ✅ UTF-8 NFKC normalized, BOM stripped, control chars filtered
- ✅ All 7 tags present in every analysis
- ✅ Length-bounded: max ~7400 chars (~2100 tokens) — fits 4k context
- ✅ Deduplicated: snippet-hash + first-200-chars analysis fingerprint
- ✅ Gold val deduplicated against train (zero overlap verified)
- ✅ DPO label-flip verified: chosen ≠ rejected conclusion (100%)
- ✅ DPO length ratio < 3.0×

## Distribution (SFT train, 2414 records)

### CWE coverage (all 14 CWEs)
```
CWE-119: 261   CWE-415: 161
CWE-120: 161   CWE-416: 195
CWE-121: 279   CWE-476: 129
CWE-122: 266   CWE-590: 207
CWE-125: 109   CWE-680: 213
CWE-126: 122   CWE-787: 128
CWE-127:  68   CWE-131: 112
```

### CoT paradigm balance
```
linear:           515  (21.3%)
counterfactual:   528  (21.9%)
reflexion:        486  (20.1%)
tree_of_thoughts: 458  (19.0%)
execution_trace:  427  (17.7%)
```

### Complexity level
```
Level 2:  1349  (55.9%)
Level 3:   678  (28.1%)
Level 4:   387  (16.0%)
```

### Label balance
```
Vulnerable (1):  1236  (51.2%)
Safe       (0):  1178  (48.8%)
```

### Coding style
```
Linux kernel:  ~12%   (kmalloc, list_head, BUG_ON)
C++ specific:  ~10%   (std::vector, smart pointers, new/delete)
Embedded C:    ~12%   (uint8_t..uint64_t, packed structs)
Standard C:    ~66%   (classic stdlib functions)
```

### Source breakdown
```
Juliet (real):              ~700  (29%)  - real CWE-labeled C files
DiverseVul (real):          ~750  (31%)  - de-tokenized CVE functions
Synthetic (Pro+Flash):      ~960  (40%)  - 5 diversity profiles + L4 push + C++ boost
```

## Recommended training config

```python
# SFT — Qwen2.5-Coder-7B-Instruct
from transformers import TrainingArguments
from peft import LoraConfig
from datasets import load_dataset

ds = load_dataset("json", data_files={
    "train":      "sft_train.jsonl",
    "validation": "sft_val.jsonl",
    "test":       "sft_test.jsonl",
    "gold":       "sft_val_gold.jsonl",   # held-out benchmark
})

lora_config = LoraConfig(
    r=16, lora_alpha=32, lora_dropout=0.05,
    target_modules=["q_proj","k_proj","v_proj","o_proj",
                    "gate_proj","up_proj","down_proj"],
    task_type="CAUSAL_LM",
)

training_args = TrainingArguments(
    output_dir="./qwen-cwe-lora",
    num_train_epochs=3,
    per_device_train_batch_size=4,
    gradient_accumulation_steps=4,        # effective batch = 16
    learning_rate=2e-4,
    warmup_ratio=0.05,
    lr_scheduler_type="cosine",
    eval_strategy="steps", eval_steps=100,
    save_strategy="steps", save_steps=200,
    logging_steps=20,
    bf16=True,
    max_seq_length=4096,
)

# DPO (after SFT)
dpo_args = dict(
    beta=0.1,
    learning_rate=5e-6,
    num_train_epochs=1,
    per_device_train_batch_size=2,
    gradient_accumulation_steps=8,
)
```

## Schema reference

### SFT (ShareGPT format)
```json
{
  "messages": [
    {"role": "system",    "content": "<paradigm-specific system prompt>"},
    {"role": "user",      "content": "...<slice>{C/C++ code}</slice>..."},
    {"role": "assistant", "content": "[SINK]: ...\n... [CONCLUSION]: VULNERABLE CWE-XXX"}
  ],
  "metadata": {
    "snippet_id": "...", "cwe_id": "CWE-XXX",
    "complexity_level": "Level 2|3|4",
    "paradigm": "linear|tree_of_thoughts|counterfactual|reflexion|execution_trace",
    "ground_truth_label": 0,
    "label_verified": true,
    "domain": "..."
  }
}
```

### DPO
```json
{
  "instruction": "...<slice>...</slice>...",
  "chosen":      "[SINK]: ...\n[CONCLUSION]: VULNERABLE CWE-XXX",
  "rejected":    "[SINK]: ...\n[CONCLUSION]: NOT_VULNERABLE CWE-XXX",
  "metadata": {
    "fallacy_type": "loop bound off-by-one|...",
    "fallacy_method": "mechanical_perturbation|api_post_hoc",
    "snippet_id": "...", "cwe_id": "CWE-XXX",
    "ground_truth_label": 0
  }
}
```

## 7-Tag analysis format

```
[SINK]:        Dangerous function: <name> at line <X>.
[DESTINATION]: Buffer size calculation: Size_B = <bytes>.
[SOURCE]:      Input size tracing: Size_A is derived from <var>.
[CONSTRAINTS]: Guards found before sink: <code or 'none'>.
[SCRATCHPAD]:  <paradigm-specific multi-step reasoning>
[MATH]:        Required safety: Size_A <= Size_B; <HOLDS or VIOLATED>.
[CONCLUSION]:  <VULNERABLE or NOT_VULNERABLE> CWE-<ID>
```
