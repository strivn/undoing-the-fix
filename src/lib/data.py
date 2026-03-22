"""Data loading utilities for CVEs, task pairs, and SWE-bench instances."""

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
CVE_DIR = DATA_DIR / "cves"
PAIRS_DIR = DATA_DIR / "task_pairs"


def load_cves() -> list[dict]:
    """Load all CVE data from data/cves/."""
    return [json.loads(p.read_text()) for p in sorted(CVE_DIR.glob("CVE-*.json"))]


def load_cve(cve_id: str) -> dict:
    """Load a single CVE by ID."""
    path = CVE_DIR / f"{cve_id}.json"
    return json.loads(path.read_text())


def load_task_pairs() -> list[dict]:
    """Load all task pairs from data/task_pairs/."""
    return [json.loads(p.read_text()) for p in sorted(PAIRS_DIR.glob("django__*.json"))]


def load_task_pair(pair_id: str) -> dict:
    """Load a single task pair by ID."""
    path = PAIRS_DIR / f"{pair_id}.json"
    return json.loads(path.read_text())


def load_django_swebench() -> list[dict]:
    """Load SWE-bench Verified, filtered to django/django."""
    from datasets import load_dataset

    ds = load_dataset("princeton-nlp/SWE-bench_Verified", split="test")
    return [x for x in ds if x["repo"] == "django/django"]


def get_swebench_instance(instances: list[dict], instance_id: str) -> dict | None:
    """Find a SWE-bench instance by ID."""
    return next((x for x in instances if x["instance_id"] == instance_id), None)


def extract_patch_files(patch: str) -> list[str]:
    """Extract file paths from a unified diff patch."""
    return [line.split(" b/")[-1] for line in patch.split("\n") if line.startswith("diff --git")]
