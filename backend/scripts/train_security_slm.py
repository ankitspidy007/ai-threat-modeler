"""QLoRA training entry point for approved Aegis security records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Fine-tune a local causal SLM with approved threat-model records.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--max-length", type=int, default=4096)
    args = parser.parse_args()

    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments
        from trl import SFTTrainer
    except ImportError as exc:
        raise SystemExit(
            "Training dependencies are missing. Install backend/requirements-training.txt first. "
            f"Original error: {exc}"
        )

    records = [json.loads(line) for line in Path(args.dataset).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not records or any((item.get("approval") or {}).get("status") != "approved" for item in records):
        raise SystemExit("Dataset is empty or contains unapproved records.")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    quantization = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(args.model, quantization_config=quantization, device_map="auto")
    dataset = Dataset.from_list([{"text": tokenizer.apply_chat_template(
        item["messages"], tokenize=False, add_generation_prompt=False,
    )} for item in records])
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        peft_config=LoraConfig(
            r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
            task_type="CAUSAL_LM", target_modules="all-linear",
        ),
        args=TrainingArguments(
            output_dir=args.output,
            num_train_epochs=args.epochs,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            learning_rate=2e-4,
            logging_steps=10,
            save_strategy="epoch",
            report_to="none",
        ),
        max_seq_length=args.max_length,
        dataset_text_field="text",
    )
    trainer.train()
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
