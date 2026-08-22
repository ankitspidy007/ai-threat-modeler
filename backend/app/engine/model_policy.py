"""How local models are resolved, and what to report when they are missing.

The product claim is that an analysis runs entirely on the machine it is
installed on. That only holds if no engine reaches for the network at analysis
time, so every model load goes through this module: loads are offline by
default, pinned to a recorded revision when one is known, and recorded so a
report can state which models actually backed it.

Fetching models is a deliberate, separate step:

    AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD=1 python tools/prefetch_models.py --write-lock

Environment:
    AEGIS_THREAT_MODEL_CACHE            directory holding model weights
    AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD   set to 1 only while prefetching
"""

import json
import logging
import os
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

LOCK_FILE = Path(__file__).resolve().parents[2] / "model_locks.json"

_TRUTHY = {"1", "true", "yes", "on"}

_status: Dict[str, Dict[str, Any]] = {}
_status_lock = Lock()


def cache_dir() -> Optional[str]:
    """Directory to read weights from, or None to use the library default."""
    configured = os.getenv("AEGIS_THREAT_MODEL_CACHE", "").strip()
    return configured or None


def downloads_allowed() -> bool:
    return os.getenv("AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD", "").strip().lower() in _TRUTHY


def _locks() -> Dict[str, str]:
    try:
        with LOCK_FILE.open("r", encoding="utf-8") as handle:
            recorded = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        logger.warning("Ignoring unreadable model lock file %s: %s", LOCK_FILE, exc)
        return {}
    models = recorded.get("models", {})
    return {
        model_id: str(entry["revision"])
        for model_id, entry in models.items()
        if isinstance(entry, dict) and entry.get("revision")
    }


def locked_revision(model_id: str) -> Optional[str]:
    """The revision this deployment is pinned to, if it has been recorded."""
    return _locks().get(model_id)


def sentence_transformer_kwargs(model_id: str) -> Dict[str, Any]:
    """Keyword arguments for sentence-transformers constructors."""
    kwargs: Dict[str, Any] = {"local_files_only": not downloads_allowed()}
    folder = cache_dir()
    if folder:
        kwargs["cache_folder"] = folder
    revision = locked_revision(model_id)
    if revision:
        kwargs["revision"] = revision
    return kwargs


def transformers_kwargs(model_id: str) -> Dict[str, Any]:
    """Keyword arguments for transformers pipelines and auto classes."""
    kwargs: Dict[str, Any] = {"local_files_only": not downloads_allowed()}
    folder = cache_dir()
    if folder:
        kwargs["cache_dir"] = folder
    revision = locked_revision(model_id)
    if revision:
        kwargs["revision"] = revision
    return kwargs


def note_model(
    model_id: str,
    role: str,
    loaded: bool,
    error: Optional[str] = None,
    fallback: Optional[str] = None,
) -> None:
    """Record the outcome of a model load for the report's engine status."""
    with _status_lock:
        _status[role] = {
            "role": role,
            "model": model_id,
            "loaded": loaded,
            "revision": locked_revision(model_id),
            "pinned": locked_revision(model_id) is not None,
            "error": _short_error(error) if error else None,
            "fallback": fallback,
        }


def model_status() -> Dict[str, Any]:
    """Which local models backed this analysis, and which degraded to a fallback."""
    with _status_lock:
        entries: List[Dict[str, Any]] = [dict(entry) for entry in _status.values()]
    entries.sort(key=lambda entry: entry["role"])
    degraded = [entry["role"] for entry in entries if not entry["loaded"]]
    return {
        "offline_enforced": not downloads_allowed(),
        "cache_dir": cache_dir(),
        "lock_file_present": LOCK_FILE.exists(),
        "models": entries,
        "degraded_roles": degraded,
        "status": "degraded" if degraded else ("active" if entries else "idle"),
    }


def reset_status_for_tests() -> None:
    with _status_lock:
        _status.clear()


def _short_error(error: str) -> str:
    """Model loaders raise multi-paragraph guidance; keep the first line."""
    first_line = str(error).strip().splitlines()[0]
    return first_line[:200]
