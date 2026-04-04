import os
import json
import sqlite3
import uuid
import threading
import time
import base64
import logging
from pathlib import Path
from collections import deque
from datetime import UTC, datetime
from flask import Flask, render_template, jsonify, send_file, request
import paho.mqtt.client as mqtt
import requests
import subprocess
import tempfile
import shutil
import contextlib
from io import BytesIO
from functools import lru_cache
from PIL import Image

DB_PATH = os.getenv("DB_PATH", "events.db")
APP_PORT = int(os.getenv("APP_PORT", "5001"))
HTTP_ACCESS_LOGS = os.getenv("HTTP_ACCESS_LOGS", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

MQTT_BROKER = os.getenv("MQTT_BROKER", "192.168.86.252")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "frigate/reviews")
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "nodered")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "password")
MQTT_CLIENT_ID = os.getenv("MQTT_CLIENT_ID", "frigate-signal")
MQTT_TLS = os.getenv("MQTT_TLS", "false").lower() in ("1", "true", "yes", "on")

FRIGATE_PUBLIC_BASE = os.getenv("FRIGATE_PUBLIC_BASE", "https://ha.xxx.com/nvr")
FRIGATE_MEDIA_PREFIX = os.getenv("FRIGATE_MEDIA_PREFIX", "/media/frigate")
FRIGATE_CLIP_PREFIX = os.getenv("FRIGATE_CLIP_PREFIX", "")
FRIGATE_VOD_BASE = os.getenv("FRIGATE_VOD_BASE", FRIGATE_PUBLIC_BASE + "/api")

INCIDENT_WINDOW_SECONDS = int(os.getenv("INCIDENT_WINDOW_SECONDS", "30"))
INCIDENT_LLM_IDLE_SECONDS = int(os.getenv("INCIDENT_LLM_IDLE_SECONDS", "15"))
INCIDENT_MIN_EVENTS = max(1, int(os.getenv("INCIDENT_MIN_EVENTS", "3")))
INCIDENT_PROCESS_BELOW_MIN_EVENTS = os.getenv(
    "INCIDENT_PROCESS_BELOW_MIN_EVENTS", "true"
).lower() in ("1", "true", "yes", "on")
INCIDENT_MIN_EVENTS_PRUNE_SECONDS = max(
    INCIDENT_WINDOW_SECONDS,
    int(os.getenv("INCIDENT_MIN_EVENTS_PRUNE_SECONDS", str(INCIDENT_WINDOW_SECONDS))),
)

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "dummy")
LLM_MODEL = os.getenv("LLM_MODEL", "")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "20"))
INCIDENT_LLM_TIMEOUT = int(os.getenv("INCIDENT_LLM_TIMEOUT", str(LLM_TIMEOUT)))
INCIDENT_LLM_MAX_RETRIES = max(1, int(os.getenv("INCIDENT_LLM_MAX_RETRIES", "2")))

TOPOLOGY_PATH = os.getenv("TOPOLOGY_PATH", "camera_topology.json")
TOPOLOGY_MAX_HOPS = int(os.getenv("TOPOLOGY_MAX_HOPS", "2"))

PROMPT_PATH = os.getenv("PROMPT_PATH", "incident_prompt.txt")
VISUAL_PROMPT_PATH = os.getenv(
    "VISUAL_PROMPT_PATH", "visual_validation_prompt.txt"
)

INCIDENT_WORKER_ENABLED = os.getenv("INCIDENT_WORKER_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
INCIDENT_WORKER_INTERVAL = float(os.getenv("INCIDENT_WORKER_INTERVAL", "5"))

NIGHT_MODE_ENABLED = os.getenv("NIGHT_MODE_ENABLED", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
DAY_START_HOUR = int(os.getenv("DAY_START_HOUR", "7"))
NIGHT_START_HOUR = int(os.getenv("NIGHT_START_HOUR", "21"))

VISUAL_VALIDATION_ENABLED = os.getenv("VISUAL_VALIDATION_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
VISUAL_MATCHER_MODE = os.getenv("VISUAL_MATCHER_MODE", "llm").strip().lower() or "llm"
VISUAL_LOCAL_MATCHER = (
    os.getenv("VISUAL_LOCAL_MATCHER", "hash").strip().lower() or "hash"
)
VISUAL_DETECTOR_MODE = (
    os.getenv("VISUAL_DETECTOR_MODE", "none").strip().lower() or "none"
)
VISUAL_DETECTOR_MODEL = os.getenv("VISUAL_DETECTOR_MODEL", "yolo11n.pt").strip()
VISUAL_DETECTOR_CONFIDENCE = float(
    os.getenv("VISUAL_DETECTOR_CONFIDENCE", "0.25")
)
VISUAL_EMBEDDING_MODEL = os.getenv(
    "VISUAL_EMBEDDING_MODEL", "openai/clip-vit-base-patch32"
).strip()
VISUAL_VALIDATION_MODEL = os.getenv("VISUAL_VALIDATION_MODEL", LLM_MODEL)
VISUAL_VALIDATION_MIN_EVENTS = int(os.getenv("VISUAL_VALIDATION_MIN_EVENTS", "3"))
VISUAL_VALIDATION_MAX_IMAGES = int(os.getenv("VISUAL_VALIDATION_MAX_IMAGES", "6"))
VISUAL_VALIDATION_THRESHOLD = float(os.getenv("VISUAL_VALIDATION_THRESHOLD", "0.45"))
VISUAL_VALIDATION_ADJACENT_THRESHOLD = float(
    os.getenv("VISUAL_VALIDATION_ADJACENT_THRESHOLD", "0.35")
)
VISUAL_LOCAL_MATCH_THRESHOLD = float(
    os.getenv("VISUAL_LOCAL_MATCH_THRESHOLD", "0.78")
)
VISUAL_LOCAL_REJECT_THRESHOLD = float(
    os.getenv("VISUAL_LOCAL_REJECT_THRESHOLD", "0.38")
)
VISUAL_HASH_SIZE = max(4, int(os.getenv("VISUAL_HASH_SIZE", "8")))
SUPPRESS_ML_BACKEND_WARNINGS = os.getenv(
    "SUPPRESS_ML_BACKEND_WARNINGS", "true"
).lower() in ("1", "true", "yes", "on")
if VISUAL_MATCHER_MODE not in {"llm", "hash", "hybrid"}:
    VISUAL_MATCHER_MODE = "llm"
if VISUAL_LOCAL_MATCHER not in {"hash", "embedding"}:
    VISUAL_LOCAL_MATCHER = "hash"
if VISUAL_DETECTOR_MODE not in {"none", "yolo"}:
    VISUAL_DETECTOR_MODE = "none"
INCIDENT_RECONCILIATION_ENABLED = os.getenv(
    "INCIDENT_RECONCILIATION_ENABLED", "true"
).lower() in ("1", "true", "yes", "on")
INCIDENT_RECONCILIATION_RECENT_SECONDS = max(
    INCIDENT_WINDOW_SECONDS,
    int(os.getenv("INCIDENT_RECONCILIATION_RECENT_SECONDS", "21600")),
)
INCIDENT_RECONCILIATION_MAX_EVENTS = max(
    10, int(os.getenv("INCIDENT_RECONCILIATION_MAX_EVENTS", "200"))
)

VIDEO_GENERATION_ENABLED = os.getenv("VIDEO_GENERATION_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
VIDEO_OUTPUT_DIR = os.getenv("VIDEO_OUTPUT_DIR", "incident_videos")
VIDEO_FFMPEG_BIN = os.getenv("VIDEO_FFMPEG_BIN", "ffmpeg")
VIDEO_SOURCE_BASE = os.getenv("VIDEO_SOURCE_BASE", FRIGATE_VOD_BASE)
VIDEO_MIN_EVENTS = int(os.getenv("VIDEO_MIN_EVENTS", "2"))
VIDEO_CLIP_PADDING_SECONDS = max(
    0, int(os.getenv("VIDEO_CLIP_PADDING_SECONDS", "1"))
)
VIDEO_OUTPUT_WIDTH = int(os.getenv("VIDEO_OUTPUT_WIDTH", "1280"))
VIDEO_OUTPUT_HEIGHT = int(os.getenv("VIDEO_OUTPUT_HEIGHT", "720"))
VIDEO_OUTPUT_FPS = int(os.getenv("VIDEO_OUTPUT_FPS", "15"))
VIDEO_OUTPUT_PROFILE = os.getenv("VIDEO_OUTPUT_PROFILE", "main")
VIDEO_OUTPUT_LEVEL = os.getenv("VIDEO_OUTPUT_LEVEL", "4.0")
VIDEO_OUTPUT_GOP_SECONDS = max(
    1, int(os.getenv("VIDEO_OUTPUT_GOP_SECONDS", "2"))
)

Path(VIDEO_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
_worker_started = False
_worker_lock = threading.Lock()


def configure_logging() -> None:
    werkzeug_level = logging.INFO if HTTP_ACCESS_LOGS else logging.WARNING
    logging.getLogger("werkzeug").setLevel(werkzeug_level)


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except Exception:
        return None


def incident_meets_minimum_event_count(event_count: int | None) -> bool:
    try:
        return int(event_count or 0) >= INCIDENT_MIN_EVENTS
    except Exception:
        return False


def normalize_timestamp(value) -> float:
    if value is None or value == "":
        return float("inf")
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("inf")


def sort_item_value(item, key: str, default=None):
    if item is None:
        return default

    try:
        if isinstance(item, dict):
            return item.get(key, default)
        return item[key]
    except (KeyError, IndexError, TypeError):
        return default


def event_sort_key(item) -> tuple[float, float, str, str]:
    start_time = normalize_timestamp(sort_item_value(item, "start_time"))
    end_time = normalize_timestamp(sort_item_value(item, "end_time"))
    updated_at = str(sort_item_value(item, "updated_at", "") or "")
    event_id = str(sort_item_value(item, "id", "") or "")
    return (start_time, end_time, updated_at, event_id)


def normalize_manual_order(value) -> tuple[int, float]:
    if value is None or value == "":
        return (1, 0.0)
    try:
        return (0, float(value))
    except (TypeError, ValueError):
        return (1, 0.0)


def display_event_sort_key(item) -> tuple[int, float, float, float, str, str]:
    manual_rank, manual_order = normalize_manual_order(
        sort_item_value(item, "manual_order")
    )
    start_time = normalize_timestamp(sort_item_value(item, "start_time"))
    end_time = normalize_timestamp(sort_item_value(item, "end_time"))
    updated_at = str(sort_item_value(item, "updated_at", "") or "")
    event_id = str(sort_item_value(item, "id", "") or "")
    return (manual_rank, manual_order, start_time, end_time, updated_at, event_id)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_label(label: str | None) -> str:
    if not label:
        return "unknown"
    label = str(label).strip().lower()
    if label.endswith("-verified"):
        label = label[:-9]
    return label or "unknown"


def load_topology() -> dict:
    path = Path(TOPOLOGY_PATH)
    if not path.exists():
        print(f"[TOPOLOGY] file not found: {path}")
        return {"zones": {}, "adjacency": {}, "hard_boundaries": []}

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "zones": data.get("zones", {}) or {},
            "adjacency": data.get("adjacency", {}) or {},
            "hard_boundaries": data.get("hard_boundaries", []) or [],
        }
    except Exception as e:
        print(f"[TOPOLOGY] failed to load {path}: {e}")
        return {"zones": {}, "adjacency": {}, "hard_boundaries": []}


def load_system_prompt() -> str:
    path = Path(PROMPT_PATH)
    if not path.exists():
        print(f"[PROMPT] file not found: {path}, using fallback")
        return (
            "You are a security incident analyst. "
            "Return only raw JSON with keys title, summary, behavior, severity."
        )

    try:
        with path.open("r", encoding="utf-8") as f:
            prompt = f.read().strip()
        print(f"[PROMPT] loaded from {path}")
        return prompt
    except Exception as e:
        print(f"[PROMPT] failed to load {path}: {e}")
        return (
            "You are a security incident analyst. "
            "Return only raw JSON with keys title, summary, behavior, severity."
        )


def visual_validation_prompt_fallback() -> str:
    return (
        "You are validating whether a surveillance event image belongs to the same subject as a recent chain of reference images. "
        "Use the reference images as a short movement history ordered in time. "
        "Decide whether the candidate image likely continues that same subject track. "
        "Account for the provided camera topology note when scoring plausibility: "
        "same camera and adjacent cameras support a match, connected cameras within a few hops are plausible, "
        "and hard boundaries or disconnected cameras should lower confidence substantially. "
        "Treat detection labels as noisy optional hints, not ground truth for identity. A generic label and a more specific label can still refer to the same subject, "
        "such as a generic vehicle label versus a delivery-brand, fleet, company, subtype, or descriptive label, or a general person label versus a named, uniformed, role-based, or descriptive person label. "
        "Do not treat differences in label specificity, branding, subtype, role, naming, or detector wording as negative evidence by themselves when the images, timing, and topology remain consistent. "
        "Only treat a label difference as meaningful if the images indicate a true subject-class mismatch or a physically implausible transition. "
        "Do not over-weight color alone for vehicles or clothing because surveillance images can shift appearance due to angle, shadow, glare, IR, compression, and front/rear/side views. "
        "Prioritize track continuity, shape, size, and movement plausibility over small color changes. "
        "Be conservative. If uncertain due to angle, distance, or occlusion, prefer low confidence rather than a false match. "
        'Return ONLY raw JSON with this format: {"match":true,"confidence":0.0,"reason":"short explanation"}'
    )


def load_visual_system_prompt() -> str:
    path = Path(VISUAL_PROMPT_PATH)
    if not path.exists():
        print(f"[VISUAL PROMPT] file not found: {path}, using fallback")
        return visual_validation_prompt_fallback()

    try:
        with path.open("r", encoding="utf-8") as f:
            prompt = f.read().strip()
        print(f"[VISUAL PROMPT] loaded from {path}")
        return prompt
    except Exception as e:
        print(f"[VISUAL PROMPT] failed to load {path}: {e}")
        return visual_validation_prompt_fallback()


TOPOLOGY = load_topology()
SYSTEM_PROMPT = load_system_prompt()
VISUAL_SYSTEM_PROMPT = load_visual_system_prompt()


def refresh_topology() -> None:
    global TOPOLOGY
    TOPOLOGY = load_topology()


def refresh_system_prompt() -> None:
    global SYSTEM_PROMPT
    SYSTEM_PROMPT = load_system_prompt()


def refresh_visual_system_prompt() -> None:
    global VISUAL_SYSTEM_PROMPT
    VISUAL_SYSTEM_PROMPT = load_visual_system_prompt()


def build_hard_boundary_set(topology: dict) -> set[tuple[str, str]]:
    pairs = set()
    for pair in topology.get("hard_boundaries", []):
        if not isinstance(pair, list) or len(pair) != 2:
            continue
        a, b = pair[0], pair[1]
        if not a or not b:
            continue
        pairs.add(tuple(sorted((a, b))))
    return pairs


def cameras_in_hard_boundary(cam_a: str, cam_b: str, topology: dict) -> bool:
    if not cam_a or not cam_b:
        return False
    boundary_set = build_hard_boundary_set(topology)
    return tuple(sorted((cam_a, cam_b))) in boundary_set


def get_adjacent_cameras(camera: str, topology: dict) -> list[str]:
    adjacency = topology.get("adjacency", {}) or {}
    neighbors = adjacency.get(camera, []) or []
    return [c for c in neighbors if c]


def cameras_have_path(
    cam_a: str, cam_b: str, topology: dict, max_hops: int = 2
) -> bool:
    if not cam_a or not cam_b:
        return False
    if cam_a == cam_b:
        return True
    if cameras_in_hard_boundary(cam_a, cam_b, topology):
        return False

    adjacency = topology.get("adjacency", {}) or {}
    if cam_a not in adjacency or cam_b not in adjacency:
        return False

    visited = {cam_a}
    queue = deque([(cam_a, 0)])

    while queue:
        current, hops = queue.popleft()
        if hops >= max_hops:
            continue

        for neighbor in get_adjacent_cameras(current, topology):
            if neighbor == cam_b:
                return True
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, hops + 1))

    return False


def cameras_are_correlatable(cam_a: str, cam_b: str, topology: dict) -> bool:
    if not cam_a or not cam_b:
        return False
    if cam_a == cam_b:
        return True
    if cameras_in_hard_boundary(cam_a, cam_b, topology):
        return False
    return cameras_have_path(cam_a, cam_b, topology, max_hops=TOPOLOGY_MAX_HOPS)


def describe_camera_topology(cam_a: str | None, cam_b: str | None, topology: dict) -> str:
    if not cam_a or not cam_b:
        return "topology unknown"
    if cam_a == cam_b:
        return "same camera"
    if cameras_in_hard_boundary(cam_a, cam_b, topology):
        return "hard boundary between cameras"

    adjacent_from_a = get_adjacent_cameras(cam_a, topology)
    adjacent_from_b = get_adjacent_cameras(cam_b, topology)
    if cam_b in adjacent_from_a or cam_a in adjacent_from_b:
        return "adjacent cameras"

    if cameras_have_path(cam_a, cam_b, topology, max_hops=TOPOLOGY_MAX_HOPS):
        return f"connected within {TOPOLOGY_MAX_HOPS} hops"

    return f"not connected within {TOPOLOGY_MAX_HOPS} hops"


def visual_validation_threshold_for(
    reference_events: list[dict], candidate_event: dict
) -> float:
    base_threshold = VISUAL_VALIDATION_THRESHOLD
    if not reference_events:
        return base_threshold

    latest_reference = reference_events[-1]
    topology_note = describe_camera_topology(
        latest_reference.get("camera"), candidate_event.get("camera"), TOPOLOGY
    )
    if topology_note in {"same camera", "adjacent cameras"}:
        return min(base_threshold, VISUAL_VALIDATION_ADJACENT_THRESHOLD)
    return base_threshold


def labels_are_visually_compatible(label_a: str | None, label_b: str | None) -> bool:
    normalized_a = normalize_label(label_a)
    normalized_b = normalize_label(label_b)

    if "unknown" in {normalized_a, normalized_b}:
        return True
    if normalized_a == normalized_b:
        return True

    compatible_pairs = {
        frozenset({"car", "person"}),
    }
    return frozenset({normalized_a, normalized_b}) in compatible_pairs


def label_can_anchor_reference(
    anchor_label: str | None, reference_label: str | None, candidate_label: str | None
) -> bool:
    normalized_anchor = normalize_label(anchor_label)
    normalized_reference = normalize_label(reference_label)
    normalized_candidate = normalize_label(candidate_label)

    if "unknown" in {normalized_reference, normalized_candidate}:
        return True
    if normalized_reference == normalized_candidate:
        return True

    # Keep compatible mixed-label events in the incident, but avoid using them
    # as the primary visual reference for later same-object comparisons.
    if normalized_candidate == normalized_anchor and normalized_reference != normalized_anchor:
        return False

    return labels_are_visually_compatible(normalized_reference, normalized_candidate)


def init_db() -> None:
    conn = get_db_connection()
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            incident_id TEXT,
            event_type TEXT,
            camera TEXT,
            start_time REAL,
            end_time REAL,
            frigate_severity TEXT,
            label TEXT,
            score INTEGER,
            severity TEXT,
            thumb_path TEXT,
            zones_json TEXT,
            objects_json TEXT,
            metadata_title TEXT,
            metadata_summary TEXT,
            metadata_scene TEXT,
            metadata_confidence REAL,
            metadata_threat_level INTEGER,
            visual_match INTEGER,
            visual_confidence REAL,
            visual_exclusion_reason TEXT,
            visual_manual_override INTEGER,
            visual_method TEXT,
            manual_order REAL,
            raw_json TEXT,
            updated_at TEXT
        )
        """
    )

    existing_columns = {
        row["name"] for row in c.execute("PRAGMA table_info(events)").fetchall()
    }

    event_migrations = {
        "incident_id": "ALTER TABLE events ADD COLUMN incident_id TEXT",
        "visual_match": "ALTER TABLE events ADD COLUMN visual_match INTEGER",
        "visual_confidence": "ALTER TABLE events ADD COLUMN visual_confidence REAL",
        "visual_exclusion_reason": "ALTER TABLE events ADD COLUMN visual_exclusion_reason TEXT",
        "visual_manual_override": "ALTER TABLE events ADD COLUMN visual_manual_override INTEGER",
        "visual_method": "ALTER TABLE events ADD COLUMN visual_method TEXT",
        "manual_order": "ALTER TABLE events ADD COLUMN manual_order REAL",
    }

    for col, sql in event_migrations.items():
        if col not in existing_columns:
            c.execute(sql)

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            start_time REAL,
            end_time REAL,
            severity TEXT,
            behavior TEXT,
            labels_json TEXT,
            cameras_json TEXT,
            path_json TEXT,
            event_count INTEGER,
            title_ai TEXT,
            summary_ai TEXT,
            scene_ai TEXT,
            thumb_url TEXT,
            review_url TEXT,
            vod_url TEXT,
            llm_status TEXT,
            llm_error TEXT,
            llm_updated_at TEXT,
            llm_ready INTEGER,
            llm_ready_reason TEXT,
            visual_status TEXT,
            visual_error TEXT,
            visual_updated_at TEXT,
            visual_confidence REAL,
            visual_method TEXT,
            video_status TEXT,
            video_error TEXT,
            video_updated_at TEXT,
            video_path TEXT,
            video_url TEXT,
            manual_editing INTEGER,
            source_updated_at TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )

    incident_columns = {
        row["name"] for row in c.execute("PRAGMA table_info(incidents)").fetchall()
    }

    incident_migrations = {
        "llm_ready": "ALTER TABLE incidents ADD COLUMN llm_ready INTEGER",
        "llm_ready_reason": "ALTER TABLE incidents ADD COLUMN llm_ready_reason TEXT",
        "visual_status": "ALTER TABLE incidents ADD COLUMN visual_status TEXT",
        "visual_error": "ALTER TABLE incidents ADD COLUMN visual_error TEXT",
        "visual_updated_at": "ALTER TABLE incidents ADD COLUMN visual_updated_at TEXT",
        "visual_confidence": "ALTER TABLE incidents ADD COLUMN visual_confidence REAL",
        "visual_method": "ALTER TABLE incidents ADD COLUMN visual_method TEXT",
        "video_status": "ALTER TABLE incidents ADD COLUMN video_status TEXT",
        "video_error": "ALTER TABLE incidents ADD COLUMN video_error TEXT",
        "video_updated_at": "ALTER TABLE incidents ADD COLUMN video_updated_at TEXT",
        "video_path": "ALTER TABLE incidents ADD COLUMN video_path TEXT",
        "video_url": "ALTER TABLE incidents ADD COLUMN video_url TEXT",
        "manual_editing": "ALTER TABLE incidents ADD COLUMN manual_editing INTEGER",
    }

    for col, sql in incident_migrations.items():
        if col not in incident_columns:
            c.execute(sql)

    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_incident_id ON events (incident_id)"
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_start_time ON events (start_time)")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_label_start_time ON events (label, start_time)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_llm_status ON incidents (llm_status)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_visual_status ON incidents (visual_status)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_source_updated_at ON incidents (source_updated_at)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_video_status ON incidents (video_status)"
    )
    conn.commit()
    conn.close()


def normalize_media_url(path: str | None) -> str | None:
    if not path:
        return None

    base = FRIGATE_PUBLIC_BASE.rstrip("/")
    media_prefix = FRIGATE_MEDIA_PREFIX.rstrip("/")
    clip_prefix = FRIGATE_CLIP_PREFIX.rstrip("/")

    if path.startswith(media_prefix):
        suffix = path[len(media_prefix) :]
        return f"{base}{clip_prefix}{suffix}"

    if path.startswith("/"):
        return f"{base}{path}"

    return f"{base}/{path}"


def build_review_url(event_id: str | None) -> str | None:
    if not event_id:
        return None
    return f"{FRIGATE_PUBLIC_BASE.rstrip('/')}/review?id={event_id}"


def build_vod_url(camera: str | None, start_time: float | None) -> str | None:
    if not camera or start_time is None:
        return None

    try:
        ts = float(start_time)
    except (TypeError, ValueError):
        return None

    after = max(0, int(ts) - 15)
    before = int(ts) + 45
    return (
        f"{FRIGATE_PUBLIC_BASE.rstrip('/')}/review"
        f"?after={after}&before={before}&cameras={camera}"
    )


def build_incident_timeline_url(
    cameras: list[str] | None, start_time: float | None, end_time: float | None
) -> str | None:
    if not cameras or start_time is None:
        return None

    try:
        start_ts = float(start_time)
    except (TypeError, ValueError):
        return None

    try:
        end_ts = float(end_time) if end_time is not None else start_ts + 45
    except (TypeError, ValueError):
        end_ts = start_ts + 45

    after = max(0, int(start_ts) - 15)
    before = int(end_ts) + 15

    unique_cameras = []
    for camera in cameras:
        if camera and camera not in unique_cameras:
            unique_cameras.append(camera)

    camera_list = ",".join(unique_cameras)
    return (
        f"{FRIGATE_PUBLIC_BASE.rstrip('/')}/review"
        f"?after={after}&before={before}&cameras={camera_list}"
    )


def build_event_clip_url(
    camera: str | None, start_time: float | None, end_time: float | None
) -> str | None:
    if not camera or start_time is None:
        return None

    try:
        start_ts = int(float(start_time))
        end_ts = int(float(end_time)) if end_time is not None else start_ts + 8
    except (TypeError, ValueError):
        return None

    if end_ts <= start_ts:
        end_ts = start_ts + 8

    start_ts = max(0, start_ts - VIDEO_CLIP_PADDING_SECONDS)
    end_ts = end_ts + VIDEO_CLIP_PADDING_SECONDS

    return (
        f"{VIDEO_SOURCE_BASE.rstrip('/')}/"
        f"{camera}/start/{start_ts}/end/{end_ts}/clip.mp4"
    )


def video_generation_should_run(event_rows: list[sqlite3.Row]) -> bool:
    if not VIDEO_GENERATION_ENABLED:
        return False
    return len(event_rows) >= VIDEO_MIN_EVENTS


def download_clip(url: str, path: Path) -> bool:
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        with path.open("wb") as f:
            f.write(resp.content)
        return True
    except Exception as e:
        print(f"[VIDEO] download failed {url}: {e}")
        return False


def build_h264_output_args() -> list[str]:
    gop_size = max(1, VIDEO_OUTPUT_FPS * VIDEO_OUTPUT_GOP_SECONDS)
    return [
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-crf",
        "23",
        "-pix_fmt",
        "yuv420p",
        "-profile:v",
        VIDEO_OUTPUT_PROFILE,
        "-level:v",
        VIDEO_OUTPUT_LEVEL,
        "-g",
        str(gop_size),
        "-keyint_min",
        str(gop_size),
        "-sc_threshold",
        "0",
        "-movflags",
        "+faststart",
    ]


def normalize_clip_for_concat(input_path: Path, output_path: Path) -> tuple[bool, str | None]:
    cmd = [
        VIDEO_FFMPEG_BIN,
        "-y",
        "-fflags",
        "+genpts+discardcorrupt",
        "-analyzeduration",
        "100M",
        "-probesize",
        "100M",
        "-i",
        str(input_path),
        "-an",
        "-vf",
        (
            f"fps={VIDEO_OUTPUT_FPS},"
            f"scale={VIDEO_OUTPUT_WIDTH}:{VIDEO_OUTPUT_HEIGHT}:"
            "force_original_aspect_ratio=decrease,"
            f"pad={VIDEO_OUTPUT_WIDTH}:{VIDEO_OUTPUT_HEIGHT}:(ow-iw)/2:(oh-ih)/2:black,"
            "setsar=1,format=yuv420p"
        ),
        "-r",
        str(VIDEO_OUTPUT_FPS),
    ]
    cmd.extend(build_h264_output_args())
    cmd.append(
        str(output_path),
    )

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        if not output_path.exists() or output_path.stat().st_size == 0:
            return False, "normalized_clip_empty"
        return True, None
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        print(f"[VIDEO] normalize failed {input_path}:", stderr)
        return False, stderr[:500] if stderr else "normalize_failed"


def concatenate_normalized_clips(
    input_paths: list[Path], output_path: Path
) -> tuple[bool, str | None]:
    if len(input_paths) < VIDEO_MIN_EVENTS:
        return False, "not_enough_normalized_clips"

    cmd = [VIDEO_FFMPEG_BIN, "-y"]
    for path in input_paths:
        cmd.extend(["-i", str(path)])

    filter_parts = []
    concat_inputs = []
    for idx, _ in enumerate(input_paths):
        filter_parts.append(
            f"[{idx}:v]settb=AVTB,setpts=PTS-STARTPTS[v{idx}]"
        )
        concat_inputs.append(f"[v{idx}]")

    filter_parts.append(
        "".join(concat_inputs) + f"concat=n={len(input_paths)}:v=1:a=0[vout]"
    )

    cmd.extend(
        [
            "-filter_complex",
            ";".join(filter_parts),
            "-map",
            "[vout]",
        ]
    )
    cmd.extend(build_h264_output_args())
    cmd.append(str(output_path))

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True, None
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        print("[VIDEO] concat failed:", stderr)
        return False, stderr[:500] if stderr else "concat_failed"


def generate_incident_video(
    incident_id: str, events: list[dict]
) -> tuple[bool, str | None]:
    if len(events) < VIDEO_MIN_EVENTS:
        return False, "not_enough_events"

    temp_dir = Path(tempfile.mkdtemp(prefix=f"incident_video_{incident_id[:8]}_"))
    output_file = Path(VIDEO_OUTPUT_DIR) / f"{incident_id}.mp4"

    try:
        normalized_files = []

        for idx, event in enumerate(events):
            clip_url = build_event_clip_url(
                event.get("camera"),
                event.get("start_time"),
                event.get("end_time"),
            )
            if not clip_url:
                continue

            downloaded_path = temp_dir / f"clip_{idx}_raw.mp4"
            normalized_path = temp_dir / f"clip_{idx}_normalized.mp4"

            if not download_clip(clip_url, downloaded_path):
                continue

            normalized, error = normalize_clip_for_concat(
                downloaded_path, normalized_path
            )
            if normalized:
                normalized_files.append(normalized_path)
            else:
                print(
                    f"[VIDEO] skipping unusable clip for incident {incident_id}: {error}"
                )

        if len(normalized_files) < VIDEO_MIN_EVENTS:
            return False, "download_failed"

        success, error = concatenate_normalized_clips(normalized_files, output_file)
        if not success:
            return False, error

        return True, str(output_file)

    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        print("[VIDEO] ffmpeg failed:", stderr)
        return False, stderr[:500] if stderr else "ffmpeg_failed"
    except Exception as e:
        print("[VIDEO] generation failed:", e)
        return False, str(e)[:500]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def is_night_timestamp(ts: float | None) -> bool:
    if not ts:
        return False
    try:
        hour = datetime.fromtimestamp(float(ts)).hour
    except Exception:
        return False
    return hour >= NIGHT_START_HOUR or hour < DAY_START_HOUR


def map_frigate_event_to_internal_severity(
    frigate_severity: str | None,
) -> tuple[int, str]:
    sev = (frigate_severity or "").strip().lower()

    if sev == "alert":
        return 1, "medium"

    if sev in ("detection", "info", ""):
        return 0, "low"

    return 0, "low"


def extract_event(payload: dict) -> dict:
    msg_type = payload.get("type", "unknown")
    data = payload.get("after") or payload.get("before") or {}
    inner = data.get("data", {}) or {}
    metadata = inner.get("metadata", {}) or {}

    objects = inner.get("objects", []) or []
    zones = inner.get("zones", []) or []

    return {
        "id": data.get("id"),
        "event_type": msg_type,
        "camera": data.get("camera", "unknown"),
        "start_time": data.get("start_time"),
        "end_time": data.get("end_time"),
        "frigate_severity": data.get("severity", "detection"),
        "thumb_path": data.get("thumb_path"),
        "objects": objects,
        "zones": zones,
        "label": normalize_label(objects[0] if objects else "unknown"),
        "metadata_title": metadata.get("title"),
        "metadata_summary": metadata.get("shortSummary"),
        "metadata_scene": metadata.get("scene"),
        "metadata_confidence": metadata.get("confidence"),
        "metadata_threat_level": metadata.get("potential_threat_level"),
        "raw_json": payload,
    }


def find_or_create_incident(conn: sqlite3.Connection, event: dict) -> str:
    event_id = event["id"]
    label = event["label"]
    start_time = event["start_time"]
    camera = event["camera"]

    existing = conn.execute(
        "SELECT incident_id FROM events WHERE id = ?",
        (event_id,),
    ).fetchone()
    if existing and existing["incident_id"]:
        return str(existing["incident_id"])

    if start_time is None:
        return str(uuid.uuid4())

    try:
        start_time_val = float(start_time)
    except (TypeError, ValueError):
        return str(uuid.uuid4())

    candidate_rows = conn.execute(
        """
        SELECT id, incident_id, camera, start_time, updated_at
        FROM events
        WHERE label = ?
          AND start_time IS NOT NULL
          AND incident_id IS NOT NULL
          AND ABS(start_time - ?) <= ?
        ORDER BY ABS(start_time - ?) ASC, updated_at DESC
        """,
        (
            label,
            start_time_val,
            INCIDENT_WINDOW_SECONDS,
            start_time_val,
        ),
    ).fetchall()

    for row in candidate_rows:
        existing_camera = row["camera"]
        if existing_camera == camera:
            return str(row["incident_id"])

    for row in candidate_rows:
        existing_camera = row["camera"]
        if cameras_are_correlatable(existing_camera, camera, TOPOLOGY):
            print(f"[TOPOLOGY] merge allowed: {existing_camera} -> {camera}")
            return str(row["incident_id"])
        else:
            print(f"[TOPOLOGY] merge rejected: {existing_camera} x {camera}")

    return str(uuid.uuid4())


def find_reconciliation_incident(
    conn: sqlite3.Connection, event: dict, exclude_event_id: str | None = None
) -> str | None:
    label = normalize_label(event.get("label"))
    camera = event.get("camera")
    start_time = event.get("start_time")

    if label == "unknown" or start_time is None:
        return None

    try:
        start_time_val = float(start_time)
    except (TypeError, ValueError):
        return None

    candidate_rows = conn.execute(
        """
        SELECT id, incident_id, camera, start_time, updated_at
        FROM events
        WHERE label = ?
          AND start_time IS NOT NULL
          AND incident_id IS NOT NULL
          AND (? IS NULL OR id != ?)
          AND ABS(start_time - ?) <= ?
        ORDER BY ABS(start_time - ?) ASC, updated_at DESC
        """,
        (
            label,
            exclude_event_id,
            exclude_event_id,
            start_time_val,
            INCIDENT_WINDOW_SECONDS,
            start_time_val,
        ),
    ).fetchall()

    for row in candidate_rows:
        if row["camera"] == camera:
            return str(row["incident_id"])

    for row in candidate_rows:
        if cameras_are_correlatable(row["camera"], camera, TOPOLOGY):
            return str(row["incident_id"])

    return None


def merge_incidents(
    conn: sqlite3.Connection, target_incident_id: str, source_incident_id: str
) -> bool:
    target = str(target_incident_id or "").strip()
    source = str(source_incident_id or "").strip()
    if not target or not source or target == source:
        return False

    source_count = conn.execute(
        "SELECT COUNT(*) AS count FROM events WHERE incident_id = ?",
        (source,),
    ).fetchone()["count"]
    if not source_count:
        return False

    timestamp = utc_now_iso()
    conn.execute(
        """
        UPDATE events
        SET incident_id = ?, updated_at = ?
        WHERE incident_id = ?
        """,
        (target, timestamp, source),
    )

    refresh_incident_record(conn, target)
    refresh_incident_record(conn, source)
    return True


def reconcile_incidents_once(
    conn: sqlite3.Connection,
    start_time: float | None = None,
    end_time: float | None = None,
    max_events: int | None = None,
    dry_run: bool = False,
) -> dict:
    if not INCIDENT_RECONCILIATION_ENABLED and not dry_run:
        return {
            "enabled": False,
            "inspected_events": 0,
            "merge_candidates": 0,
            "merged_incidents": [],
        }

    clauses = [
        "incident_id IS NOT NULL",
        "start_time IS NOT NULL",
    ]
    params: list[object] = []

    if start_time is None:
        start_time = max(0.0, time.time() - INCIDENT_RECONCILIATION_RECENT_SECONDS)
    clauses.append("start_time >= ?")
    params.append(float(start_time))

    if end_time is not None:
        clauses.append("start_time <= ?")
        params.append(float(end_time))

    limit = int(max_events or INCIDENT_RECONCILIATION_MAX_EVENTS)
    params.append(limit)

    rows = conn.execute(
        f"""
        SELECT id, incident_id, camera, label, start_time, updated_at
        FROM events
        WHERE {' AND '.join(clauses)}
        ORDER BY start_time ASC, updated_at ASC
        LIMIT ?
        """,
        params,
    ).fetchall()

    merged_incidents: list[dict] = []
    merged_pairs: set[tuple[str, str]] = set()

    for row in rows:
        current_incident_id = str(row["incident_id"] or "").strip()
        if not current_incident_id:
            continue

        preferred_incident_id = find_reconciliation_incident(
            conn,
            {
                "id": row["id"],
                "camera": row["camera"],
                "label": row["label"],
                "start_time": row["start_time"],
            },
            exclude_event_id=str(row["id"]),
        )
        if not preferred_incident_id or preferred_incident_id == current_incident_id:
            continue

        pair = tuple(sorted((current_incident_id, preferred_incident_id)))
        if pair in merged_pairs:
            continue

        current_start = conn.execute(
            "SELECT MIN(start_time) AS start_time FROM events WHERE incident_id = ?",
            (current_incident_id,),
        ).fetchone()["start_time"]
        preferred_start = conn.execute(
            "SELECT MIN(start_time) AS start_time FROM events WHERE incident_id = ?",
            (preferred_incident_id,),
        ).fetchone()["start_time"]

        target_incident_id = preferred_incident_id
        source_incident_id = current_incident_id
        if (
            current_start is not None
            and preferred_start is not None
            and float(current_start) < float(preferred_start)
        ):
            target_incident_id = current_incident_id
            source_incident_id = preferred_incident_id

        merged_pairs.add(tuple(sorted((source_incident_id, target_incident_id))))
        merged_incidents.append(
            {
                "source_incident_id": source_incident_id,
                "target_incident_id": target_incident_id,
                "trigger_event_id": str(row["id"]),
            }
        )

        if dry_run:
            continue

        merge_incidents(conn, target_incident_id, source_incident_id)

    return {
        "enabled": INCIDENT_RECONCILIATION_ENABLED,
        "inspected_events": len(rows),
        "merge_candidates": len(merged_incidents),
        "merged_incidents": merged_incidents,
    }


def classify_incident_fallback(
    initial_severity: str,
    labels: list[str],
    cameras: list[str],
    event_rows: list[sqlite3.Row],
) -> str:
    if initial_severity == "high":
        return "concerning"

    if NIGHT_MODE_ENABLED:
        if any(is_night_timestamp(row["start_time"]) for row in event_rows):
            if "person" in labels:
                return "monitor"

    if initial_severity == "medium":
        return "monitor"

    return "routine"


def extract_json_from_text(text: str) -> dict:
    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    if "```json" in text:
        try:
            chunk = text.split("```json", 1)[1].split("```", 1)[0].strip()
            return json.loads(chunk)
        except Exception:
            pass

    if "```" in text:
        parts = text.split("```")
        for part in parts:
            candidate = part.strip()
            if not candidate:
                continue
            if candidate.startswith("json"):
                candidate = candidate[4:].strip()
            try:
                return json.loads(candidate)
            except Exception:
                continue

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        return json.loads(candidate)

    raise ValueError("No valid JSON object found in model response")


def visual_validation_should_run(event_rows: list[sqlite3.Row]) -> bool:
    if not VISUAL_VALIDATION_ENABLED:
        return False

    if len(event_rows) < VISUAL_VALIDATION_MIN_EVENTS:
        return False

    unique_cameras = {row["camera"] for row in event_rows if row["camera"]}
    if len(unique_cameras) < 2:
        return False

    thumb_count = sum(1 for row in event_rows if row["thumb_path"])
    if thumb_count < 2:
        return False

    return True


def mime_from_url_or_path(path: str | None) -> str:
    if not path:
        return "image/jpeg"
    lower = path.lower()
    if lower.endswith(".webp"):
        return "image/webp"
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        return "image/jpeg"
    return "image/jpeg"


def fetch_image_as_data_url(url: str, source_path: str | None = None) -> str | None:
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        content = resp.content
        mime = resp.headers.get("Content-Type") or mime_from_url_or_path(source_path)
        encoded = base64.b64encode(content).decode("ascii")
        return f"data:{mime};base64,{encoded}"
    except Exception as e:
        print(f"[VISUAL] failed to fetch image {url}: {e}")
        return None


def fetch_image_bytes(url: str) -> bytes | None:
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.content
    except Exception as e:
        print(f"[VISUAL] failed to fetch raw image {url}: {e}")
        return None


def open_image_bytes(image_bytes: bytes) -> Image.Image:
    with Image.open(BytesIO(image_bytes)) as image:
        return image.convert("RGB")


@contextlib.contextmanager
def suppress_native_stderr(enabled: bool):
    if not enabled:
        yield
        return

    stderr_fd = None
    saved_stderr_fd = None
    try:
        stderr_fd = os.open(os.devnull, os.O_WRONLY)
        saved_stderr_fd = os.dup(2)
        os.dup2(stderr_fd, 2)
        yield
    finally:
        if saved_stderr_fd is not None:
            os.dup2(saved_stderr_fd, 2)
            os.close(saved_stderr_fd)
        if stderr_fd is not None:
            os.close(stderr_fd)


@lru_cache(maxsize=1)
def get_embedding_runtime():
    # Torch/native backends can emit one-time CPU capability warnings that add log noise.
    with suppress_native_stderr(SUPPRESS_ML_BACKEND_WARNINGS):
        import torch
        from transformers import AutoProcessor, AutoModel

        processor = AutoProcessor.from_pretrained(VISUAL_EMBEDDING_MODEL)
        model = AutoModel.from_pretrained(VISUAL_EMBEDDING_MODEL)
    model.eval()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    return {
        "torch": torch,
        "processor": processor,
        "model": model,
        "device": device,
    }


@lru_cache(maxsize=1)
def get_yolo_runtime():
    with suppress_native_stderr(SUPPRESS_ML_BACKEND_WARNINGS):
        from ultralytics import YOLO

    return YOLO(VISUAL_DETECTOR_MODEL)


def preferred_detection_labels(label: str | None) -> set[str]:
    normalized = normalize_label(label)
    label_map = {
        "person": {"person"},
        "car": {"car"},
        "truck": {"truck"},
        "bus": {"bus"},
        "motorcycle": {"motorcycle"},
        "bicycle": {"bicycle"},
        "dog": {"dog"},
        "cat": {"cat"},
    }
    preferred = label_map.get(normalized, set())
    return preferred or {normalized}


def crop_image_with_yolo(image: Image.Image, label: str | None) -> Image.Image:
    if VISUAL_DETECTOR_MODE != "yolo":
        return image

    try:
        model = get_yolo_runtime()
        results = model.predict(image, conf=VISUAL_DETECTOR_CONFIDENCE, verbose=False)
    except Exception as e:
        print(f"[VISUAL] yolo detection failed: {e}")
        return image

    if not results:
        return image

    result = results[0]
    boxes = getattr(result, "boxes", None)
    names = getattr(result, "names", {}) or {}
    xyxy = getattr(boxes, "xyxy", None) if boxes is not None else None
    if xyxy is None:
        return image

    preferred = preferred_detection_labels(label)
    selected_box = None
    selected_score = -1.0

    xyxy_list = xyxy.tolist() if hasattr(xyxy, "tolist") else []
    conf_list = boxes.conf.tolist() if getattr(boxes, "conf", None) is not None and hasattr(boxes.conf, "tolist") else []
    cls_list = boxes.cls.tolist() if getattr(boxes, "cls", None) is not None and hasattr(boxes.cls, "tolist") else []

    for idx, coords in enumerate(xyxy_list):
        confidence = float(conf_list[idx]) if idx < len(conf_list) else 0.0
        cls_idx = int(cls_list[idx]) if idx < len(cls_list) else -1
        detected_name = str(names.get(cls_idx, "")).strip().lower()
        score = confidence
        if detected_name in preferred:
            score += 1.0
        if score > selected_score:
            selected_score = score
            selected_box = coords

    if not selected_box:
        return image

    x1, y1, x2, y2 = [int(round(value)) for value in selected_box[:4]]
    width, height = image.size
    x1 = max(0, min(x1, width))
    y1 = max(0, min(y1, height))
    x2 = max(x1 + 1, min(x2, width))
    y2 = max(y1 + 1, min(y2, height))
    return image.crop((x1, y1, x2, y2))


def prepare_local_match_image(event: dict) -> Image.Image | None:
    thumb_url = event.get("thumb_url")
    if not thumb_url:
        return None

    image_bytes = fetch_image_bytes(thumb_url)
    if not image_bytes:
        return None

    try:
        image = open_image_bytes(image_bytes)
    except Exception as e:
        print(f"[VISUAL] failed to decode image {event.get('id')}: {e}")
        return None

    return crop_image_with_yolo(image, event.get("label"))


def image_average_hash(
    image: Image.Image, hash_size: int = VISUAL_HASH_SIZE
) -> list[int]:
    grayscale = image.convert("L").resize((hash_size, hash_size))
    pixels = list(grayscale.getdata())

    if not pixels:
        return [0] * (hash_size * hash_size)

    average = sum(pixels) / len(pixels)
    return [1 if pixel >= average else 0 for pixel in pixels]


def hash_similarity(hash_a: list[int], hash_b: list[int]) -> float:
    if not hash_a or not hash_b or len(hash_a) != len(hash_b):
        return 0.0

    distance = sum(1 for a, b in zip(hash_a, hash_b) if a != b)
    return max(0.0, 1.0 - (distance / len(hash_a)))


def topology_match_score(reference_camera: str | None, candidate_camera: str | None) -> float:
    topology_note = describe_camera_topology(reference_camera, candidate_camera, TOPOLOGY)
    if topology_note == "same camera":
        return 1.0
    if topology_note == "adjacent cameras":
        return 0.85
    if topology_note.startswith("connected within "):
        return 0.65
    if topology_note == "hard boundary between cameras":
        return 0.1
    return 0.35


def temporal_match_score(
    reference_time: float | None, candidate_time: float | None
) -> float:
    try:
        if reference_time is None or candidate_time is None:
            return 0.4
        delta = abs(float(candidate_time) - float(reference_time))
    except Exception:
        return 0.4

    if delta <= INCIDENT_WINDOW_SECONDS:
        return 1.0
    if delta <= 90:
        return 0.8
    if delta <= 300:
        return 0.6
    if delta <= 900:
        return 0.45
    return 0.25


def embedding_similarity(image_a: Image.Image, image_b: Image.Image) -> float:
    try:
        runtime = get_embedding_runtime()
    except Exception as e:
        print(f"[VISUAL] embedding runtime unavailable: {e}")
        return 0.0

    torch = runtime["torch"]
    processor = runtime["processor"]
    model = runtime["model"]
    device = runtime["device"]

    try:
        inputs = processor(images=[image_a, image_b], return_tensors="pt")
        inputs = {key: value.to(device) for key, value in inputs.items()}

        with torch.no_grad():
            if hasattr(model, "get_image_features"):
                embeddings = model.get_image_features(
                    pixel_values=inputs["pixel_values"]
                )
            else:
                outputs = model(**inputs)
                if getattr(outputs, "pooler_output", None) is not None:
                    embeddings = outputs.pooler_output
                elif getattr(outputs, "image_embeds", None) is not None:
                    embeddings = outputs.image_embeds
                else:
                    embeddings = outputs.last_hidden_state.mean(dim=1)

        embeddings = torch.nn.functional.normalize(embeddings, p=2, dim=1)
        similarity = torch.sum(embeddings[0] * embeddings[1]).item()
        return max(0.0, min(1.0, (similarity + 1.0) / 2.0))
    except Exception as e:
        print(f"[VISUAL] embedding similarity failed: {e}")
        return 0.0


def local_hash_match_score(reference_events: list[dict], candidate_event: dict) -> dict | None:
    if not reference_events or not candidate_event.get("thumb_url"):
        return None

    candidate_image = prepare_local_match_image(candidate_event)
    if not candidate_image:
        return None

    try:
        candidate_hash = image_average_hash(candidate_image)
    except Exception as e:
        print(f"[VISUAL] failed to hash candidate {candidate_event.get('id')}: {e}")
        return None

    best_score = -1.0
    best_similarity = 0.0
    best_topology = 0.0
    best_temporal = 0.0
    best_reference = None
    candidate_label = normalize_label(candidate_event.get("label"))

    for reference in reference_events:
        reference_image = prepare_local_match_image(reference)
        if not reference_image:
            continue

        try:
            reference_hash = image_average_hash(reference_image)
        except Exception as e:
            print(f"[VISUAL] failed to hash reference {reference.get('id')}: {e}")
            continue

        similarity = hash_similarity(reference_hash, candidate_hash)
        topology_score = topology_match_score(
            reference.get("camera"), candidate_event.get("camera")
        )
        temporal_score = temporal_match_score(
            reference.get("start_time"), candidate_event.get("start_time")
        )
        label_score = (
            1.0
            if labels_are_visually_compatible(reference.get("label"), candidate_label)
            else 0.0
        )

        score = (
            (0.6 * similarity)
            + (0.2 * topology_score)
            + (0.15 * temporal_score)
            + (0.05 * label_score)
        )

        if score > best_score:
            best_score = score
            best_similarity = similarity
            best_topology = topology_score
            best_temporal = temporal_score
            best_reference = reference

    if best_reference is None:
        return None

    return {
        "match": best_score >= VISUAL_VALIDATION_THRESHOLD,
        "confidence": max(0.0, min(1.0, best_score)),
        "reason": (
            f"local hash score={best_score:.2f} image={best_similarity:.2f} "
            f"topology={best_topology:.2f} time={best_temporal:.2f} "
            f"ref={best_reference.get('id')}"
        ),
        "method": "hash",
    }


def local_embedding_match_score(
    reference_events: list[dict], candidate_event: dict
) -> dict | None:
    if not reference_events or not candidate_event.get("thumb_url"):
        return None

    candidate_image = prepare_local_match_image(candidate_event)
    if not candidate_image:
        return None

    best_score = -1.0
    best_similarity = 0.0
    best_topology = 0.0
    best_temporal = 0.0
    best_reference = None
    candidate_label = normalize_label(candidate_event.get("label"))

    for reference in reference_events:
        reference_image = prepare_local_match_image(reference)
        if not reference_image:
            continue

        similarity = embedding_similarity(reference_image, candidate_image)
        topology_score = topology_match_score(
            reference.get("camera"), candidate_event.get("camera")
        )
        temporal_score = temporal_match_score(
            reference.get("start_time"), candidate_event.get("start_time")
        )
        label_score = (
            1.0
            if labels_are_visually_compatible(reference.get("label"), candidate_label)
            else 0.0
        )

        score = (
            (0.7 * similarity)
            + (0.15 * topology_score)
            + (0.1 * temporal_score)
            + (0.05 * label_score)
        )

        if score > best_score:
            best_score = score
            best_similarity = similarity
            best_topology = topology_score
            best_temporal = temporal_score
            best_reference = reference

    if best_reference is None:
        return None

    return {
        "match": best_score >= VISUAL_VALIDATION_THRESHOLD,
        "confidence": max(0.0, min(1.0, best_score)),
        "reason": (
            f"local embedding score={best_score:.2f} image={best_similarity:.2f} "
            f"topology={best_topology:.2f} time={best_temporal:.2f} "
            f"ref={best_reference.get('id')}"
        ),
        "method": "embedding",
    }


def local_visual_match_score(reference_events: list[dict], candidate_event: dict) -> dict | None:
    if VISUAL_LOCAL_MATCHER == "embedding":
        result = local_embedding_match_score(reference_events, candidate_event)
        if result:
            return result
    return local_hash_match_score(reference_events, candidate_event)


def call_visual_validation(
    reference_events: list[dict], candidate_event: dict
) -> dict | None:
    if not LLM_BASE_URL or not VISUAL_VALIDATION_MODEL:
        return None

    if not reference_events or not candidate_event.get("thumb_url"):
        return None

    prepared_references = []
    reference_limit = max(1, VISUAL_VALIDATION_MAX_IMAGES - 1)
    for event in reference_events[-reference_limit:]:
        if not event.get("thumb_url"):
            continue
        data_url = fetch_image_as_data_url(event["thumb_url"], event.get("thumb_path"))
        if not data_url:
            continue
        topology_note = describe_camera_topology(
            event.get("camera"), candidate_event.get("camera"), TOPOLOGY
        )
        prepared_references.append(
            {
                "event_id": event["id"],
                "camera": event.get("camera"),
                "time": event.get("start_time"),
                "topology_note": topology_note,
                "image_data_url": data_url,
            }
        )

    if not prepared_references:
        return None

    candidate_data_url = fetch_image_as_data_url(
        candidate_event["thumb_url"], candidate_event.get("thumb_path")
    )
    if not candidate_data_url:
        return None

    system_prompt = VISUAL_SYSTEM_PROMPT or visual_validation_prompt_fallback()

    content = [
        {
            "type": "text",
            "text": (
                "Reference images first, oldest to newest. Then the candidate image. "
                "Evaluate whether the candidate likely shows the same subject continuing through the reference chain. "
                "Confidence must be 0.0 to 1.0. Include a short reason. "
                "For adjacent cameras, continuity over time matters more than small apparent color shifts. "
                "A generic label and a more specific label may still describe the same subject, so do not treat label naming differences alone as a mismatch. "
                "Reject only when the visual evidence or movement continuity shows a real mismatch."
            ),
        }
    ]

    for reference in prepared_references:
        content.append(
            {
                "type": "text",
                "text": (
                    f"Reference event_id={reference['event_id']} "
                    f"camera={reference.get('camera')} "
                    f"time={reference.get('time')} "
                    f"topology_to_candidate={reference.get('topology_note')}"
                ),
            }
        )
        content.append(
            {
                "type": "image_url",
                "image_url": {"url": reference["image_data_url"]},
            }
        )

    content.append(
        {
            "type": "text",
            "text": (
                f"Candidate event_id={candidate_event['id']} "
                f"camera={candidate_event.get('camera')} "
                f"time={candidate_event.get('start_time')}"
            ),
        }
    )
    content.append({"type": "image_url", "image_url": {"url": candidate_data_url}})

    def post_visual_request(user_content: list[dict], extra_system_text: str = "") -> str:
        system_text = system_prompt
        if extra_system_text:
            system_text = f"{system_prompt} {extra_system_text}"

        print(f"[VISUAL] calling {LLM_BASE_URL} model={VISUAL_VALIDATION_MODEL}")
        response = requests.post(
            f"{LLM_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": VISUAL_VALIDATION_MODEL,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": system_text},
                    {"role": "user", "content": user_content},
                ],
            },
            timeout=LLM_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        message_content = data["choices"][0]["message"]["content"]

        if isinstance(message_content, list):
            message_content = "".join(
                part.get("text", "")
                for part in message_content
                if isinstance(part, dict)
            )
        return str(message_content or "")

    try:
        message_content = post_visual_request(content)
        try:
            parsed = extract_json_from_text(message_content)
        except Exception:
            preview = " ".join(message_content.strip().split())
            print(
                f"[VISUAL] parse failed for candidate {candidate_event.get('id')}: "
                f"{preview[:500]}"
            )

            retry_content = content + [
                {
                    "type": "text",
                    "text": (
                        "Your previous reply was not valid JSON. "
                        "Retry now and return ONLY one raw JSON object with keys "
                        "match, confidence, and reason. Do not include markdown."
                    ),
                }
            ]
            message_content = post_visual_request(
                retry_content,
                extra_system_text=(
                    "Your response must be valid JSON only. "
                    "Do not add prose, code fences, or commentary."
                ),
            )
            parsed = extract_json_from_text(message_content)

        try:
            confidence = float(parsed.get("confidence", 0))
        except Exception:
            confidence = 0.0

        return {
            "match": bool(parsed.get("match")),
            "confidence": confidence,
            "reason": parsed.get("reason"),
        }
    except Exception as e:
        print(
            f"[VISUAL] validation failed for candidate {candidate_event.get('id')}: {e}"
        )
        return None


def resolve_visual_match(
    reference_events: list[dict], candidate_event: dict
) -> dict | None:
    mode = VISUAL_MATCHER_MODE

    if mode == "hash":
        return local_visual_match_score(reference_events, candidate_event)

    if mode == "hybrid":
        local_result = local_visual_match_score(reference_events, candidate_event)
        if local_result:
            confidence = float(local_result.get("confidence", 0.0))
            if confidence >= VISUAL_LOCAL_MATCH_THRESHOLD:
                local_result["match"] = True
                local_result["reason"] = (
                    f"{local_result.get('reason')} auto-accepted locally"
                )
                return local_result
            if confidence <= VISUAL_LOCAL_REJECT_THRESHOLD:
                local_result["match"] = False
                local_result["reason"] = (
                    f"{local_result.get('reason')} auto-rejected locally"
                )
                return local_result

        llm_result = call_visual_validation(reference_events, candidate_event)
        if llm_result:
            llm_result["method"] = "llm"
            return llm_result
        return local_result

    result = call_visual_validation(reference_events, candidate_event)
    if result:
        result["method"] = "llm"
    return result


def clean_visual_exclusion_reason(reason: object) -> str | None:
    if reason is None:
        return None

    text = " ".join(str(reason).strip().split())
    if not text:
        return None
    return text[:160]


def build_visual_exclusion_reason(
    result_item: dict | None, confidence: float
) -> str | None:
    reason = clean_visual_exclusion_reason(
        result_item.get("reason") if result_item else None
    )
    if reason:
        return reason

    if result_item and result_item.get("match") and confidence < VISUAL_VALIDATION_THRESHOLD:
        confidence_pct = int(round(confidence * 100))
        threshold_pct = int(round(VISUAL_VALIDATION_THRESHOLD * 100))
        return (
            f"Matched the anchor at {confidence_pct}% confidence, below the "
            f"{threshold_pct}% threshold."
        )

    if result_item:
        return "Did not appear to show the same subject as the anchor event."

    return "Validation did not return a match result for this event."


def call_incident_llm(
    events_payload: list[dict], cameras: list[str], labels: list[str], severity: str
) -> dict | None:
    if not LLM_BASE_URL or not LLM_MODEL:
        return None

    ordered_events = sorted(events_payload, key=event_sort_key)

    compact_events = []
    for event in ordered_events:
        compact_events.append(
            {
                "camera": event.get("camera"),
                "time": event.get("start_time"),
                "event_type": event.get("event_type"),
                "label": event.get("label"),
                "frigate_severity": event.get("frigate_severity"),
                "title": event.get("title"),
                "summary": event.get("summary"),
                "scene": event.get("scene"),
                "threat_level": event.get("threat_level"),
            }
        )

    is_night = NIGHT_MODE_ENABLED and any(
        is_night_timestamp(event.get("start_time")) for event in ordered_events
    )

    user_prompt = {
        "severity": severity,
        "labels": labels,
        "cameras": cameras,
        "is_night": is_night,
        "events": compact_events,
    }

    last_error = None
    for attempt in range(1, INCIDENT_LLM_MAX_RETRIES + 1):
        try:
            print(
                f"[LLM] incident synthesis calling {LLM_BASE_URL} model={LLM_MODEL} "
                f"attempt={attempt}/{INCIDENT_LLM_MAX_RETRIES} timeout={INCIDENT_LLM_TIMEOUT}s"
            )
            response = requests.post(
                f"{LLM_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {LLM_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": LLM_MODEL,
                    "temperature": 0.2,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": json.dumps(user_prompt, ensure_ascii=False),
                        },
                    ],
                },
                timeout=INCIDENT_LLM_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            content = data["choices"][0]["message"]["content"]
            if isinstance(content, list):
                content = "".join(
                    part.get("text", "") for part in content if isinstance(part, dict)
                )

            parsed = extract_json_from_text(content)

            behavior = parsed.get("behavior")
            if behavior not in {"routine", "monitor", "concerning"}:
                behavior = "monitor"

            severity_ai = parsed.get("severity")
            if severity_ai not in {"low", "medium", "high"}:
                severity_ai = None

            return {
                "title_ai": parsed.get("title"),
                "summary_ai": parsed.get("summary"),
                "behavior": behavior,
                "severity_ai": severity_ai,
            }
        except Exception as e:
            last_error = e
            print(
                f"LLM incident synthesis failed on attempt {attempt}/"
                f"{INCIDENT_LLM_MAX_RETRIES}: {e}"
            )
            if attempt < INCIDENT_LLM_MAX_RETRIES:
                time.sleep(min(2 * attempt, 5))

    return None


def incident_is_ready_for_llm(
    event_rows: list[sqlite3.Row], visual_status: str | None
) -> tuple[bool, str]:
    if not event_rows:
        return False, "no_events"

    if (
        not INCIDENT_PROCESS_BELOW_MIN_EVENTS
        and not incident_meets_minimum_event_count(len(event_rows))
    ):
        return False, "waiting_for_min_events"

    if visual_validation_should_run(event_rows):
        if visual_status not in ("ready", "skipped", "error"):
            return False, "waiting_for_visual_validation"

    for row in event_rows:
        if row["metadata_title"] or row["metadata_summary"] or row["metadata_scene"]:
            return True, "event_genai_present"

    latest_update = max((row["updated_at"] or "" for row in event_rows), default="")
    if latest_update:
        try:
            latest_dt = parse_iso_timestamp(latest_update)
            if not latest_dt:
                raise ValueError("invalid latest_update timestamp")
            idle_seconds = (utc_now() - latest_dt).total_seconds()
            if idle_seconds >= INCIDENT_LLM_IDLE_SECONDS:
                return True, f"idle_{int(idle_seconds)}s"
        except Exception:
            pass

    return False, "waiting_for_genai_or_idle"


def upsert_event(conn: sqlite3.Connection, event: dict) -> str:
    score, severity = map_frigate_event_to_internal_severity(event["frigate_severity"])
    incident_id = find_or_create_incident(conn, event)

    conn.execute(
        """
        INSERT INTO events (
            id, incident_id, event_type, camera, start_time, end_time, frigate_severity,
            label, score, severity, thumb_path, zones_json, objects_json,
            metadata_title, metadata_summary, metadata_scene,
            metadata_confidence, metadata_threat_level,
            raw_json, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            incident_id=COALESCE(events.incident_id, excluded.incident_id),
            event_type=excluded.event_type,
            camera=excluded.camera,
            start_time=COALESCE(excluded.start_time, events.start_time),
            end_time=COALESCE(excluded.end_time, events.end_time),
            frigate_severity=excluded.frigate_severity,
            label=excluded.label,
            score=excluded.score,
            severity=excluded.severity,
            thumb_path=COALESCE(excluded.thumb_path, events.thumb_path),
            zones_json=excluded.zones_json,
            objects_json=excluded.objects_json,
            metadata_title=COALESCE(excluded.metadata_title, events.metadata_title),
            metadata_summary=COALESCE(excluded.metadata_summary, events.metadata_summary),
            metadata_scene=COALESCE(excluded.metadata_scene, events.metadata_scene),
            metadata_confidence=COALESCE(excluded.metadata_confidence, events.metadata_confidence),
            metadata_threat_level=COALESCE(excluded.metadata_threat_level, events.metadata_threat_level),
            raw_json=excluded.raw_json,
            updated_at=excluded.updated_at
        """,
        (
            event["id"],
            incident_id,
            event["event_type"],
            event["camera"],
            event["start_time"],
            event["end_time"],
            event["frigate_severity"],
            event["label"],
            score,
            severity,
            event["thumb_path"],
            json.dumps(event["zones"]),
            json.dumps(event["objects"]),
            event["metadata_title"],
            event["metadata_summary"],
            event["metadata_scene"],
            event["metadata_confidence"],
            event["metadata_threat_level"],
            json.dumps(event["raw_json"]),
            utc_now_iso(),
        ),
    )

    return incident_id


def refresh_incident_record(conn: sqlite3.Connection, incident_id: str) -> None:
    event_rows = conn.execute(
        """
        SELECT id, incident_id, event_type, camera, start_time, end_time, frigate_severity,
               label, score, severity, thumb_path,
               metadata_title, metadata_summary, metadata_scene,
               metadata_confidence, metadata_threat_level,
               visual_match, visual_confidence, visual_exclusion_reason, visual_manual_override, visual_method, manual_order,
               zones_json, objects_json, updated_at
        FROM events
        WHERE incident_id = ?
        """,
        (incident_id,),
    ).fetchall()
    event_rows = sorted(event_rows, key=display_event_sort_key)

    if not event_rows:
        conn.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
        return

    start_time = min(
        (row["start_time"] for row in event_rows if row["start_time"] is not None),
        default=None,
    )

    end_candidates = [
        (row["end_time"] if row["end_time"] is not None else row["start_time"])
        for row in event_rows
        if row["start_time"] is not None
    ]
    end_time = max(end_candidates) if end_candidates else start_time

    any_alert = any(
        (row["frigate_severity"] or "").lower() == "alert" for row in event_rows
    )
    incident_severity = "medium" if any_alert else "low"
    source_updated_at = max((row["updated_at"] or "" for row in event_rows), default="")

    cameras = []
    labels = []
    best_scored_event = None
    best_ai_event = None
    path_steps = []
    event_count = len(event_rows)

    for row in event_rows:
        if row["camera"] not in cameras:
            cameras.append(row["camera"])
        if row["label"] not in labels:
            labels.append(row["label"])

        if row["metadata_title"] or row["metadata_summary"]:
            if best_ai_event is None:
                best_ai_event = row

        if best_scored_event is None or (row["score"] or 0) > (
            best_scored_event["score"] or 0
        ):
            best_scored_event = row

        path_steps.append(
            {
                "camera": row["camera"],
                "time": row["start_time"],
                "label": row["label"],
                "event_type": row["event_type"],
            }
        )

    best_event = best_ai_event or best_scored_event
    thumb_url = normalize_media_url(best_event["thumb_path"]) if best_event else None
    review_url = build_review_url(best_event["id"]) if best_event else None
    vod_url = build_incident_timeline_url(cameras, start_time, end_time)

    behavior = classify_incident_fallback(
        incident_severity,
        labels,
        cameras,
        event_rows,
    )

    existing_incident = conn.execute(
        """
        SELECT llm_status, llm_updated_at, title_ai, summary_ai, behavior, severity,
               source_updated_at, created_at, llm_error,
               visual_status, visual_error, visual_updated_at, visual_confidence,
               video_status, video_error, video_updated_at, video_path, video_url,
               manual_editing
        FROM incidents
        WHERE incident_id = ?
        """,
        (incident_id,),
    ).fetchone()

    manual_editing = bool(existing_incident["manual_editing"]) if existing_incident else False

    visual_should_run = visual_validation_should_run(event_rows)
    visual_status = "pending" if visual_should_run else "skipped"
    visual_error = None
    visual_updated_at = None
    visual_confidence = None

    if existing_incident:
        existing_source_updated_at = existing_incident["source_updated_at"] or ""
        existing_visual_status = existing_incident["visual_status"] or (
            "pending" if visual_should_run else "skipped"
        )

        if existing_source_updated_at == source_updated_at:
            visual_status = existing_visual_status
            visual_error = existing_incident["visual_error"]
            visual_updated_at = existing_incident["visual_updated_at"]
            visual_confidence = existing_incident["visual_confidence"]
        else:
            visual_status = "pending" if visual_should_run else "skipped"
            visual_error = None
            visual_updated_at = None
            visual_confidence = None

    video_should_run = video_generation_should_run(event_rows)
    video_status = "pending" if video_should_run else "skipped"
    video_error = None
    video_updated_at = None
    video_path = None
    video_url = None

    if existing_incident:
        existing_source_updated_at = existing_incident["source_updated_at"] or ""
        existing_video_status = existing_incident["video_status"] or (
            "pending" if video_should_run else "skipped"
        )

        if existing_source_updated_at == source_updated_at:
            video_status = existing_video_status
            video_error = existing_incident["video_error"]
            video_updated_at = existing_incident["video_updated_at"]
            video_path = existing_incident["video_path"]
            video_url = existing_incident["video_url"]
        else:
            video_status = "pending" if video_should_run else "skipped"
            video_error = None
            video_updated_at = None
            video_path = None
            video_url = None

    llm_ready, llm_ready_reason = incident_is_ready_for_llm(event_rows, visual_status)

    llm_status = "pending" if llm_ready else "waiting"
    llm_updated_at = None
    llm_error = None
    title_ai = best_event["metadata_title"] if best_event else None
    summary_ai = best_event["metadata_summary"] if best_event else None
    scene_ai = best_event["metadata_scene"] if best_event else None
    created_at = (
        existing_incident["created_at"]
        if existing_incident and existing_incident["created_at"]
        else utc_now_iso()
    )

    if existing_incident:
        existing_source_updated_at = existing_incident["source_updated_at"] or ""

        if existing_source_updated_at == source_updated_at:
            llm_updated_at = existing_incident["llm_updated_at"]
            llm_error = existing_incident["llm_error"]

            if existing_incident["title_ai"]:
                title_ai = existing_incident["title_ai"]
            if existing_incident["summary_ai"]:
                summary_ai = existing_incident["summary_ai"]
            if existing_incident["behavior"]:
                behavior = existing_incident["behavior"]
            if existing_incident["severity"]:
                incident_severity = existing_incident["severity"]

            existing_status = existing_incident["llm_status"] or "waiting"

            if existing_status == "waiting" and llm_ready:
                llm_status = "pending"
                llm_updated_at = None
                llm_error = None
            elif existing_status == "ready" and llm_ready:
                llm_status = "ready"
            elif existing_status == "error" and not llm_ready:
                llm_status = "waiting"
            else:
                llm_status = existing_status
        else:
            llm_status = "pending" if llm_ready else "waiting"
            llm_updated_at = None
            llm_error = None

    if manual_editing and existing_incident:
        llm_status = existing_incident["llm_status"] or "waiting"
        llm_updated_at = existing_incident["llm_updated_at"]
        llm_error = existing_incident["llm_error"]
        visual_status = existing_incident["visual_status"] or visual_status
        visual_error = existing_incident["visual_error"]
        visual_updated_at = existing_incident["visual_updated_at"]
        visual_confidence = existing_incident["visual_confidence"]
        video_status = existing_incident["video_status"] or video_status
        video_error = existing_incident["video_error"]
        video_updated_at = existing_incident["video_updated_at"]
        video_path = existing_incident["video_path"]
        video_url = existing_incident["video_url"]

    conn.execute(
        """
        INSERT INTO incidents (
            incident_id, start_time, end_time, severity, behavior,
            labels_json, cameras_json, path_json, event_count,
            title_ai, summary_ai, scene_ai,
            thumb_url, review_url, vod_url,
            llm_status, llm_error, llm_updated_at,
            llm_ready, llm_ready_reason,
            visual_status, visual_error, visual_updated_at, visual_confidence,
            video_status, video_error, video_updated_at, video_path, video_url,
            manual_editing,
            source_updated_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(incident_id) DO UPDATE SET
            start_time=excluded.start_time,
            end_time=excluded.end_time,
            severity=excluded.severity,
            behavior=excluded.behavior,
            labels_json=excluded.labels_json,
            cameras_json=excluded.cameras_json,
            path_json=excluded.path_json,
            event_count=excluded.event_count,
            title_ai=excluded.title_ai,
            summary_ai=excluded.summary_ai,
            scene_ai=excluded.scene_ai,
            thumb_url=excluded.thumb_url,
            review_url=excluded.review_url,
            vod_url=excluded.vod_url,
            llm_status=excluded.llm_status,
            llm_error=excluded.llm_error,
            llm_updated_at=excluded.llm_updated_at,
            llm_ready=excluded.llm_ready,
            llm_ready_reason=excluded.llm_ready_reason,
            visual_status=excluded.visual_status,
            visual_error=excluded.visual_error,
            visual_updated_at=excluded.visual_updated_at,
            visual_confidence=excluded.visual_confidence,
            video_status=excluded.video_status,
            video_error=excluded.video_error,
            video_updated_at=excluded.video_updated_at,
            video_path=excluded.video_path,
            video_url=excluded.video_url,
            manual_editing=excluded.manual_editing,
            source_updated_at=excluded.source_updated_at,
            updated_at=excluded.updated_at
        """,
        (
            incident_id,
            start_time,
            end_time,
            incident_severity,
            behavior,
            json.dumps(labels),
            json.dumps(cameras),
            json.dumps(path_steps),
            event_count,
            title_ai,
            summary_ai,
            scene_ai,
            thumb_url,
            review_url,
            vod_url,
            llm_status,
            llm_error,
            llm_updated_at,
            1 if llm_ready else 0,
            llm_ready_reason,
            visual_status,
            visual_error,
            visual_updated_at,
            visual_confidence,
            video_status,
            video_error,
            video_updated_at,
            video_path,
            video_url,
            1 if manual_editing else 0,
            source_updated_at,
            created_at,
            utc_now_iso(),
        ),
    )


def refresh_waiting_incidents_to_pending() -> None:
    conn = get_db_connection()
    try:
        rows_to_refresh = conn.execute(
            """
            SELECT DISTINCT incident_id
            FROM (
                SELECT incident_id
                FROM incidents
                WHERE (
                        llm_status = 'waiting'
                        OR visual_status = 'pending'
                        OR video_status IS NULL
                        OR video_status = 'pending'
                    )
                  AND COALESCE(manual_editing, 0) = 0

                UNION

                SELECT e.incident_id
                FROM events e
                LEFT JOIN incidents i ON i.incident_id = e.incident_id
                WHERE e.incident_id IS NOT NULL
                  AND i.incident_id IS NULL
            )
            WHERE incident_id IS NOT NULL
            """
        ).fetchall()

        for row in rows_to_refresh:
            refresh_incident_record(conn, row["incident_id"])

        conn.commit()
    finally:
        conn.close()


def prune_small_incidents_once(conn: sqlite3.Connection) -> dict[str, int]:
    if INCIDENT_MIN_EVENTS <= 1:
        return {"deleted_incidents": 0, "deleted_events": 0}

    now = utc_now()
    incident_rows = conn.execute(
        """
        SELECT incident_id, event_count, updated_at, source_updated_at, manual_editing
        FROM incidents
        WHERE event_count < ?
        """,
        (INCIDENT_MIN_EVENTS,),
    ).fetchall()

    deleted_incidents = 0
    deleted_events = 0

    for row in incident_rows:
        if bool(row["manual_editing"]):
            continue

        reference_dt = parse_iso_timestamp(row["source_updated_at"]) or parse_iso_timestamp(
            row["updated_at"]
        )
        if not reference_dt:
            continue

        idle_seconds = (now - reference_dt).total_seconds()
        if idle_seconds < INCIDENT_MIN_EVENTS_PRUNE_SECONDS:
            continue

        incident_id = row["incident_id"]
        event_total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()[0]
        conn.execute("DELETE FROM events WHERE incident_id = ?", (incident_id,))
        conn.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
        deleted_incidents += 1
        deleted_events += int(event_total or 0)

    return {
        "deleted_incidents": deleted_incidents,
        "deleted_events": deleted_events,
    }


def reorder_event_in_incident(event_id: str, direction: int) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT id, incident_id
            FROM events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()

        if not row:
            return None

        incident_id = row["incident_id"]
        if not incident_id:
            raise ValueError("event_incident_missing")

        event_rows = conn.execute(
            """
            SELECT id, incident_id, start_time, end_time, manual_order, updated_at
            FROM events
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchall()

        ordered_events = sorted(event_rows, key=display_event_sort_key)
        event_ids = [str(item["id"]) for item in ordered_events]

        try:
            current_index = event_ids.index(str(event_id))
        except ValueError:
            return None

        target_index = current_index + int(direction)
        if target_index < 0 or target_index >= len(event_ids):
            touched_ids = _set_incident_manual_editing(conn, [str(incident_id)], True)
            conn.commit()
            return {
                "event_id": str(event_id),
                "incident_id": str(incident_id),
                "manual_order_changed": False,
                "editing_incident_ids": touched_ids,
            }

        moved_id = event_ids.pop(current_index)
        event_ids.insert(target_index, moved_id)

        timestamp = utc_now_iso()
        for index, ordered_event_id in enumerate(event_ids, start=1):
            conn.execute(
                """
                UPDATE events
                SET manual_order = ?, updated_at = ?
                WHERE id = ?
                """,
                (float(index), timestamp, ordered_event_id),
            )

        refresh_incident_record(conn, str(incident_id))
        touched_ids = _set_incident_manual_editing(conn, [str(incident_id)], True)

        conn.commit()
        return {
            "event_id": str(event_id),
            "incident_id": str(incident_id),
            "manual_order_changed": True,
            "editing_incident_ids": touched_ids,
        }
    finally:
        conn.close()


def remove_event_from_incident(event_id: str) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT id, incident_id
            FROM events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()

        if not row:
            return None

        incident_id = row["incident_id"]
        if not incident_id:
            raise ValueError("event_incident_missing")

        touched_ids = _set_incident_manual_editing(conn, [str(incident_id)], True)
        conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
        refresh_incident_record(conn, str(incident_id))
        conn.commit()

        remaining = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM events
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()["count"]

        return {
            "event_id": str(event_id),
            "incident_id": str(incident_id),
            "editing_incident_ids": touched_ids,
            "incident_deleted": remaining == 0,
            "remaining_event_count": int(remaining or 0),
        }
    finally:
        conn.close()


def _set_incident_manual_editing(
    conn: sqlite3.Connection,
    incident_ids: list[str],
    editing: bool,
    reprocess: bool = True,
) -> list[str]:
    normalized_ids = []
    for incident_id in incident_ids:
        value = str(incident_id or "").strip()
        if value and value not in normalized_ids:
            normalized_ids.append(value)

    if not normalized_ids:
        return []

    timestamp = utc_now_iso()
    for incident_id in normalized_ids:
        conn.execute(
            """
            INSERT INTO incidents (incident_id, manual_editing, updated_at, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                manual_editing = excluded.manual_editing,
                updated_at = excluded.updated_at
            """,
            (incident_id, 1 if editing else 0, timestamp, timestamp),
        )

        if editing or not reprocess:
            continue

        conn.execute(
            """
            UPDATE incidents
            SET llm_status = CASE
                    WHEN llm_ready = 1 THEN 'pending'
                    ELSE 'waiting'
                END,
                llm_error = NULL,
                llm_updated_at = NULL,
                visual_status = CASE
                    WHEN visual_status IN ('ready', 'pending', 'error') THEN 'pending'
                    ELSE visual_status
                END,
                visual_error = NULL,
                visual_updated_at = NULL,
                visual_confidence = NULL,
                video_status = CASE
                    WHEN video_status IN ('ready', 'pending', 'error') OR video_status IS NULL THEN 'pending'
                    ELSE video_status
                END,
                video_error = NULL,
                video_updated_at = NULL,
                video_path = NULL,
                video_url = NULL,
                updated_at = ?
            WHERE incident_id = ?
            """,
            (timestamp, incident_id),
        )

        refresh_incident_record(conn, incident_id)

    return normalized_ids


def set_incident_manual_editing(
    incident_ids: list[str], editing: bool, reprocess: bool = True
) -> list[str]:
    conn = get_db_connection()
    try:
        result = _set_incident_manual_editing(
            conn, incident_ids, editing, reprocess=reprocess
        )
        conn.commit()
        return result
    finally:
        conn.close()


def retry_incident_llm(incident_id: str) -> dict | None:
    conn = get_db_connection()
    try:
        incident = conn.execute(
            """
            SELECT incident_id, manual_editing
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()

        if not incident:
            return None

        if incident["manual_editing"]:
            raise ValueError("incident_editing_in_progress")

        refresh_incident_record(conn, incident_id)

        refreshed = conn.execute(
            """
            SELECT incident_id, llm_ready, llm_status
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()

        if not refreshed:
            return None

        next_status = "pending" if refreshed["llm_ready"] else "waiting"
        conn.execute(
            """
            UPDATE incidents
            SET llm_status = ?,
                llm_error = NULL,
                llm_updated_at = NULL,
                updated_at = ?
            WHERE incident_id = ?
            """,
            (next_status, utc_now_iso(), incident_id),
        )
        conn.commit()

        if next_status == "pending":
            process_pending_incidents_once()

        return {
            "incident_id": incident_id,
            "llm_status": next_status,
            "llm_ready": bool(refreshed["llm_ready"]),
        }
    finally:
        conn.close()


def override_visual_exclusion(event_id: str) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT id, incident_id
            FROM events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()

        if not row:
            return None

        incident_id = row["incident_id"]
        if not incident_id:
            raise ValueError("event_incident_missing")

        touched_ids = _set_incident_manual_editing(conn, [str(incident_id)], True)

        conn.execute(
            """
            UPDATE events
            SET visual_manual_override = 1,
                visual_match = 1,
                visual_exclusion_reason = NULL
            WHERE id = ?
            """,
            (event_id,),
        )

        refresh_incident_record(conn, incident_id)
        conn.commit()

        return {
            "event_id": str(event_id),
            "incident_id": str(incident_id),
            "visual_manual_override": True,
            "editing_incident_ids": touched_ids,
        }
    finally:
        conn.close()


def process_pending_visual_validation_once() -> None:
    if not VISUAL_VALIDATION_ENABLED or not LLM_BASE_URL or not VISUAL_VALIDATION_MODEL:
        return

    conn = get_db_connection()
    try:
        incidents_to_process = conn.execute(
            """
            SELECT incident_id
            FROM incidents
            WHERE visual_status = 'pending'
              AND COALESCE(manual_editing, 0) = 0
            ORDER BY updated_at ASC
            LIMIT 5
            """
        ).fetchall()

        for incident in incidents_to_process:
            incident_id = incident["incident_id"]

            try:
                rows = conn.execute(
                    """
                    SELECT id, camera, label, start_time, thumb_path, updated_at, visual_match, visual_confidence, manual_order
                           , visual_manual_override, visual_method
                    FROM events
                    WHERE incident_id = ?
                    """,
                    (incident_id,),
                ).fetchall()
                rows = sorted(rows, key=display_event_sort_key)

                if not rows:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET visual_status = 'skipped',
                            visual_error = NULL,
                            visual_updated_at = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (utc_now_iso(), utc_now_iso(), incident_id),
                    )
                    conn.commit()
                    continue

                if not visual_validation_should_run(rows):
                    conn.execute(
                        """
                        UPDATE incidents
                        SET visual_status = 'skipped',
                            visual_error = NULL,
                            visual_updated_at = ?,
                            visual_confidence = NULL,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (utc_now_iso(), utc_now_iso(), incident_id),
                    )
                    conn.commit()
                    refresh_incident_record(conn, incident_id)
                    conn.commit()
                    continue

                events_payload = []
                for row in rows:
                    thumb_url = normalize_media_url(row["thumb_path"])
                    if not thumb_url:
                        continue
                    events_payload.append(
                        {
                            "id": row["id"],
                            "camera": row["camera"],
                            "start_time": row["start_time"],
                            "label": row["label"],
                            "thumb_path": row["thumb_path"],
                            "thumb_url": thumb_url,
                            "visual_manual_override": bool(row["visual_manual_override"]),
                            "visual_confidence": row["visual_confidence"],
                            "visual_method": row["visual_method"],
                        }
                    )

                if len(events_payload) < 2:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET visual_status = 'skipped',
                            visual_error = NULL,
                            visual_updated_at = ?,
                            visual_confidence = NULL,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (utc_now_iso(), utc_now_iso(), incident_id),
                    )
                    conn.commit()
                    refresh_incident_record(conn, incident_id)
                    conn.commit()
                    continue

                anchor_event = events_payload[0]
                conn.execute(
                    """
                    UPDATE events
                    SET visual_match = 1,
                        visual_confidence = 1.0,
                        visual_method = 'anchor',
                        visual_exclusion_reason = NULL
                    WHERE id = ?
                    """,
                    (anchor_event["id"],),
                )

                accepted_chain = [anchor_event]
                chain_confidences = []
                anchor_label = normalize_label(anchor_event.get("label"))

                for event in events_payload[1:]:
                    candidate_label = normalize_label(event.get("label"))

                    if event.get("visual_manual_override"):
                        conn.execute(
                            """
                            UPDATE events
                            SET visual_match = 1,
                                visual_method = 'manual',
                                visual_exclusion_reason = NULL
                            WHERE id = ?
                            """,
                            (event["id"],),
                        )
                        accepted_chain.append(event)
                        continue

                    eligible_references = [
                        chain_event
                        for chain_event in accepted_chain
                        if label_can_anchor_reference(
                            anchor_label,
                            chain_event.get("label"),
                            candidate_label,
                        )
                    ]
                    if not eligible_references:
                        eligible_references = [accepted_chain[-1]]

                    if len(eligible_references) > 1:
                        reference_events = [
                            eligible_references[-2],
                            eligible_references[-1],
                        ]
                    else:
                        reference_events = [eligible_references[-1]]
                    result = resolve_visual_match(reference_events, event)

                    if not result:
                        conn.execute(
                            """
                            UPDATE incidents
                            SET visual_status = 'error',
                                visual_error = 'Visual validation failed',
                                visual_updated_at = ?,
                                updated_at = ?
                            WHERE incident_id = ?
                            """,
                            (utc_now_iso(), utc_now_iso(), incident_id),
                        )
                        conn.commit()
                        refresh_incident_record(conn, incident_id)
                        conn.commit()
                        break

                    confidence = float(result.get("confidence", 0.0))
                    method = str(result.get("method") or VISUAL_MATCHER_MODE)
                    chain_confidences.append(confidence)
                    effective_threshold = visual_validation_threshold_for(
                        reference_events, event
                    )
                    match = (
                        1
                        if (
                            result.get("match")
                            and confidence >= effective_threshold
                        )
                        else 0
                    )
                    exclusion_reason = (
                        build_visual_exclusion_reason(result, confidence)
                        if match == 0
                        else None
                    )

                    conn.execute(
                        """
                        UPDATE events
                        SET visual_match = ?,
                            visual_confidence = ?,
                            visual_method = ?,
                            visual_exclusion_reason = ?
                        WHERE id = ?
                        """,
                        (
                            match,
                            confidence,
                            method,
                            exclusion_reason,
                            event["id"],
                        ),
                    )
                    if match == 1:
                        accepted_chain.append(event)

                else:
                    overall_confidence = (
                        sum(chain_confidences) / len(chain_confidences)
                        if chain_confidences
                        else 1.0
                    )

                    conn.execute(
                        """
                        UPDATE incidents
                        SET visual_status = 'ready',
                            visual_error = NULL,
                            visual_updated_at = ?,
                            visual_confidence = ?,
                            visual_method = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            utc_now_iso(),
                            overall_confidence,
                            VISUAL_MATCHER_MODE,
                            utc_now_iso(),
                            incident_id,
                        ),
                    )
                    conn.commit()

                    refresh_incident_record(conn, incident_id)
                    conn.commit()

            except Exception as e:
                conn.execute(
                    """
                    UPDATE incidents
                    SET visual_status = 'error',
                        visual_error = ?,
                        visual_updated_at = ?,
                        updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        str(e)[:500],
                        utc_now_iso(),
                        utc_now_iso(),
                        incident_id,
                    ),
                )
                conn.commit()
                refresh_incident_record(conn, incident_id)
                conn.commit()
    finally:
        conn.close()


def process_pending_incident_videos_once() -> None:
    if not VIDEO_GENERATION_ENABLED:
        return

    conn = get_db_connection()
    try:
        incidents_to_process = conn.execute(
            """
            SELECT incident_id, visual_status
            FROM incidents
            WHERE video_status = 'pending'
              AND COALESCE(manual_editing, 0) = 0
            ORDER BY updated_at ASC
            LIMIT 10
            """
        ).fetchall()

        for incident in incidents_to_process:
            incident_id = incident["incident_id"]

            try:
                event_rows = conn.execute(
                    """
                    SELECT id, camera, start_time, end_time, visual_match, manual_order, updated_at
                    FROM events
                    WHERE incident_id = ?
                    """,
                    (incident_id,),
                ).fetchall()
                event_rows = sorted(event_rows, key=display_event_sort_key)

                if not event_rows or not video_generation_should_run(event_rows):
                    conn.execute(
                        """
                        UPDATE incidents
                        SET video_status = 'skipped',
                            video_error = NULL,
                            video_updated_at = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            utc_now_iso(),
                            utc_now_iso(),
                            incident_id,
                        ),
                    )
                    conn.commit()
                    continue

                visible_events = []
                for row in event_rows:
                    if (
                        incident["visual_status"] == "ready"
                        and row["visual_match"] == 0
                    ):
                        continue
                    visible_events.append(
                        {
                            "id": row["id"],
                            "camera": row["camera"],
                            "start_time": row["start_time"],
                            "end_time": row["end_time"],
                        }
                    )

                if len(visible_events) < VIDEO_MIN_EVENTS:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET video_status = 'skipped',
                            video_error = NULL,
                            video_updated_at = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            utc_now_iso(),
                            utc_now_iso(),
                            incident_id,
                        ),
                    )
                    conn.commit()
                    continue

                success, result = generate_incident_video(incident_id, visible_events)

                if success:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET video_status = 'ready',
                            video_error = NULL,
                            video_updated_at = ?,
                            video_path = ?,
                            video_url = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            utc_now_iso(),
                            result,
                            f"/video/{incident_id}",
                            utc_now_iso(),
                            incident_id,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET video_status = 'error',
                            video_error = ?,
                            video_updated_at = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            result,
                            utc_now_iso(),
                            utc_now_iso(),
                            incident_id,
                        ),
                    )

                conn.commit()

            except Exception as e:
                conn.execute(
                    """
                    UPDATE incidents
                    SET video_status = 'error',
                        video_error = ?,
                        video_updated_at = ?,
                        updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        str(e)[:500],
                        utc_now_iso(),
                        utc_now_iso(),
                        incident_id,
                    ),
                )
                conn.commit()
    finally:
        conn.close()


def process_pending_incidents_once() -> None:
    if not (LLM_BASE_URL and LLM_MODEL):
        return

    conn = get_db_connection()
    try:
        incidents_to_process = conn.execute(
            """
            SELECT incident_id, severity, labels_json, cameras_json, source_updated_at,
                   llm_status, llm_ready, llm_ready_reason, visual_status
            FROM incidents
            WHERE llm_status = 'pending'
              AND llm_ready = 1
              AND COALESCE(manual_editing, 0) = 0
            ORDER BY updated_at ASC
            LIMIT 5
            """
        ).fetchall()

        for incident in incidents_to_process:
            incident_id = incident["incident_id"]

            try:
                event_rows = conn.execute(
                    """
                    SELECT id, incident_id, event_type, camera, start_time, end_time, frigate_severity,
                           label, score, severity, thumb_path,
                           metadata_title, metadata_summary, metadata_scene,
                           metadata_confidence, metadata_threat_level,
                           visual_match, visual_confidence, manual_order,
                           zones_json, objects_json, updated_at
                    FROM events
                    WHERE incident_id = ?
                    """,
                    (incident_id,),
                ).fetchall()
                event_rows = sorted(event_rows, key=display_event_sort_key)

                if not event_rows:
                    continue

                events_payload = []
                ai_scenes = []

                for row in event_rows:
                    # If visual validation completed, exclude rejected events from incident AI
                    if (
                        incident["visual_status"] == "ready"
                        and row["visual_match"] == 0
                    ):
                        continue

                    events_payload.append(
                        {
                            "id": row["id"],
                            "incident_id": row["incident_id"],
                            "event_type": row["event_type"],
                            "camera": row["camera"],
                            "start_time": row["start_time"],
                            "end_time": row["end_time"],
                            "frigate_severity": row["frigate_severity"],
                            "label": row["label"],
                            "score": row["score"],
                            "severity": row["severity"],
                            "thumb_path": row["thumb_path"],
                            "thumb_url": normalize_media_url(row["thumb_path"]),
                            "review_url": build_review_url(row["id"]),
                            "vod_url": build_vod_url(row["camera"], row["start_time"]),
                            "title": row["metadata_title"],
                            "summary": row["metadata_summary"],
                            "scene": row["metadata_scene"],
                            "confidence": row["metadata_confidence"],
                            "threat_level": row["metadata_threat_level"],
                            "visual_match": row["visual_match"],
                            "visual_confidence": row["visual_confidence"],
                            "zones": json.loads(row["zones_json"] or "[]"),
                            "objects": json.loads(row["objects_json"] or "[]"),
                            "updated_at": row["updated_at"],
                        }
                    )

                    if row["metadata_scene"]:
                        ai_scenes.append(row["metadata_scene"])

                if not events_payload:
                    continue

                labels = []
                cameras = []
                for ev in events_payload:
                    if ev["label"] not in labels:
                        labels.append(ev["label"])
                    if ev["camera"] not in cameras:
                        cameras.append(ev["camera"])

                severity = incident["severity"]

                llm_result = call_incident_llm(
                    events_payload=events_payload,
                    cameras=cameras,
                    labels=labels,
                    severity=severity,
                )

                if llm_result:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET title_ai = ?,
                            summary_ai = ?,
                            behavior = ?,
                            severity = COALESCE(?, severity),
                            scene_ai = COALESCE(scene_ai, ?),
                            llm_status = 'ready',
                            llm_error = NULL,
                            llm_updated_at = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            llm_result.get("title_ai"),
                            llm_result.get("summary_ai"),
                            llm_result.get("behavior"),
                            llm_result.get("severity_ai"),
                            ai_scenes[0] if ai_scenes else None,
                            utc_now_iso(),
                            utc_now_iso(),
                            incident_id,
                        ),
                    )
                    conn.commit()
                else:
                    error_message = "LLM synthesis failed or returned invalid JSON"
                    conn.execute(
                        """
                        UPDATE incidents
                        SET llm_status = 'error',
                            llm_error = ?,
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            error_message,
                            utc_now_iso(),
                            incident_id,
                        ),
                    )
                    conn.commit()

            except Exception as e:
                conn.execute(
                    """
                    UPDATE incidents
                    SET llm_status = 'error',
                        llm_error = ?,
                        updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        str(e)[:500],
                        utc_now_iso(),
                        incident_id,
                    ),
                )
                conn.commit()
    finally:
        conn.close()


def incident_worker_loop() -> None:
    print("[WORKER] incident worker started")
    while True:
        try:
            conn = get_db_connection()
            try:
                reconcile_incidents_once(conn)
                prune_small_incidents_once(conn)
                conn.commit()
            finally:
                conn.close()
            refresh_waiting_incidents_to_pending()
            process_pending_visual_validation_once()
            process_pending_incident_videos_once()
            process_pending_incidents_once()
        except Exception as e:
            print(f"[WORKER] error: {e}")
        time.sleep(INCIDENT_WORKER_INTERVAL)


def start_incident_worker() -> None:
    global _worker_started
    if not INCIDENT_WORKER_ENABLED:
        print("[WORKER] disabled")
        return

    with _worker_lock:
        if _worker_started:
            return
        thread = threading.Thread(target=incident_worker_loop, daemon=True)
        thread.start()
        _worker_started = True


def on_connect(client, userdata, flags, reason_code, properties=None):
    print("Connected to MQTT:", reason_code)
    client.subscribe(MQTT_TOPIC)
    print("Subscribed to:", MQTT_TOPIC)


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        event = extract_event(payload)

        if not event["id"]:
            return

        conn = get_db_connection()
        incident_id = upsert_event(conn, event)
        refresh_incident_record(conn, incident_id)
        conn.commit()
        conn.close()

        print(
            f"[{event['event_type']}] "
            f"{event['camera']} | {event['label']} | incident={incident_id}"
        )
    except Exception as e:
        print("MQTT ERROR:", e)


def start_mqtt() -> None:
    kwargs = {}
    try:
        kwargs["callback_api_version"] = mqtt.CallbackAPIVersion.VERSION2
    except Exception:
        pass

    client = mqtt.Client(client_id=MQTT_CLIENT_ID, **kwargs)

    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

    if MQTT_TLS:
        client.tls_set()

    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, incident_id, event_type, camera, start_time, end_time, frigate_severity,
               label, score, severity, thumb_path,
               metadata_title, metadata_summary, metadata_scene,
               metadata_confidence, metadata_threat_level,
               visual_match, visual_confidence, visual_exclusion_reason, visual_manual_override,
               zones_json, objects_json, updated_at
        FROM events
        WHERE incident_id IN (
            SELECT incident_id
            FROM incidents
            WHERE event_count >= ?
        )
        ORDER BY updated_at DESC
        LIMIT 100
        """
        ,
        (INCIDENT_MIN_EVENTS,),
    ).fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append(
            {
                "id": r["id"],
                "incident_id": r["incident_id"],
                "event_type": r["event_type"],
                "camera": r["camera"],
                "start_time": r["start_time"],
                "end_time": r["end_time"],
                "frigate_severity": r["frigate_severity"],
                "label": r["label"],
                "score": r["score"],
                "severity": r["severity"],
                "thumb_path": r["thumb_path"],
                "thumb_url": normalize_media_url(r["thumb_path"]),
                "review_url": build_review_url(r["id"]),
                "vod_url": build_vod_url(r["camera"], r["start_time"]),
                "title": r["metadata_title"],
                "summary": r["metadata_summary"],
                "scene": r["metadata_scene"],
                "confidence": r["metadata_confidence"],
                "threat_level": r["metadata_threat_level"],
                "visual_match": r["visual_match"],
                "visual_confidence": r["visual_confidence"],
                "visual_exclusion_reason": r["visual_exclusion_reason"],
                "visual_manual_override": bool(r["visual_manual_override"]),
                "zones": json.loads(r["zones_json"] or "[]"),
                "objects": json.loads(r["objects_json"] or "[]"),
                "updated_at": r["updated_at"],
            }
        )
    return jsonify(results)


@app.route("/api/incidents")
def api_incidents():
    conn = get_db_connection()
    incident_rows = conn.execute(
        """
        SELECT *
        FROM incidents
        WHERE event_count >= ?
        ORDER BY updated_at DESC
        LIMIT 50
        """
        ,
        (INCIDENT_MIN_EVENTS,),
    ).fetchall()

    results = []
    for incident in incident_rows:
        event_rows = conn.execute(
            """
            SELECT id, incident_id, event_type, camera, start_time, end_time, frigate_severity,
                   label, score, severity, thumb_path,
                   metadata_title, metadata_summary, metadata_scene,
                   metadata_confidence, metadata_threat_level,
                   visual_match, visual_confidence, visual_exclusion_reason, visual_manual_override, manual_order,
                   zones_json, objects_json, updated_at
            FROM events
            WHERE incident_id = ?
            """,
            (incident["incident_id"],),
        ).fetchall()
        event_rows = sorted(event_rows, key=display_event_sort_key)

        all_events_payload = []
        visible_events_payload = []

        for row in event_rows:
            item = {
                "id": row["id"],
                "incident_id": row["incident_id"],
                "event_type": row["event_type"],
                "camera": row["camera"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "manual_order": row["manual_order"],
                "frigate_severity": row["frigate_severity"],
                "label": row["label"],
                "score": row["score"],
                "severity": row["severity"],
                "thumb_path": row["thumb_path"],
                "thumb_url": normalize_media_url(row["thumb_path"]),
                "review_url": build_review_url(row["id"]),
                "vod_url": build_vod_url(row["camera"], row["start_time"]),
                "title": row["metadata_title"],
                "summary": row["metadata_summary"],
                "scene": row["metadata_scene"],
                "confidence": row["metadata_confidence"],
                "threat_level": row["metadata_threat_level"],
                "visual_match": row["visual_match"],
                "visual_confidence": row["visual_confidence"],
                "visual_exclusion_reason": row["visual_exclusion_reason"],
                "visual_manual_override": bool(row["visual_manual_override"]),
                "zones": json.loads(row["zones_json"] or "[]"),
                "objects": json.loads(row["objects_json"] or "[]"),
                "updated_at": row["updated_at"],
            }
            all_events_payload.append(item)
            visible_events_payload.append(item)

        visible_cameras = []
        for ev in all_events_payload:
            if ev["camera"] not in visible_cameras:
                visible_cameras.append(ev["camera"])

        horizontal_path = [
            {
                "camera": ev["camera"],
                "time": ev["start_time"],
                "label": ev["label"],
                "event_type": ev["event_type"],
            }
            for ev in all_events_payload
        ]

        excluded_event_count = sum(
            1
            for ev in all_events_payload
            if incident["visual_status"] == "ready" and ev["visual_match"] == 0
        )

        results.append(
            {
                "incident_id": incident["incident_id"],
                "severity": incident["severity"],
                "behavior": incident["behavior"],
                "event_count": incident["event_count"],
                "start_time": incident["start_time"],
                "end_time": incident["end_time"],
                "updated_at": incident["updated_at"],
                "llm_cached": incident["llm_status"] == "ready",
                "llm_status": incident["llm_status"],
                "llm_error": incident["llm_error"],
                "llm_ready": bool(incident["llm_ready"]),
                "llm_ready_reason": incident["llm_ready_reason"],
                "visual_status": incident["visual_status"],
                "visual_error": incident["visual_error"],
                "visual_confidence": incident["visual_confidence"],
                "video_status": incident["video_status"],
                "video_error": incident["video_error"],
                "video_url": incident["video_url"],
                "manual_editing": bool(incident["manual_editing"]),
                "excluded_event_count": excluded_event_count,
                "cameras": visible_cameras,
                "labels": json.loads(incident["labels_json"] or "[]"),
                "title": incident["title_ai"],
                "summary": incident["summary_ai"],
                "scene": incident["scene_ai"],
                "path_text": " → ".join(
                    [
                        step.get("camera", "")
                        for step in horizontal_path
                        if step.get("camera")
                    ]
                ),
                "horizontal_path": horizontal_path,
                "thumb_url": incident["thumb_url"],
                "review_url": incident["review_url"],
                "vod_url": incident["vod_url"],
                "events": visible_events_payload,
                "all_events": all_events_payload,
            }
        )

    conn.close()
    return jsonify(results)


@app.route("/api/topology/reload", methods=["GET", "POST"])
def api_topology_reload():
    refresh_topology()
    return jsonify(
        {
            "status": "reloaded",
            "topology_path": TOPOLOGY_PATH,
            "topology_cameras": sorted(list((TOPOLOGY.get("adjacency") or {}).keys())),
        }
    )


@app.route("/api/prompt/reload", methods=["GET", "POST"])
def api_prompt_reload():
    refresh_system_prompt()
    refresh_visual_system_prompt()
    return jsonify(
        {
            "status": "reloaded",
            "prompt_path": PROMPT_PATH,
            "length": len(SYSTEM_PROMPT),
            "visual_prompt_path": VISUAL_PROMPT_PATH,
            "visual_length": len(VISUAL_SYSTEM_PROMPT),
        }
    )


@app.route("/api/worker/run", methods=["GET", "POST"])
def api_worker_run():
    conn = get_db_connection()
    try:
        reconcile_incidents_once(conn)
        prune_small_incidents_once(conn)
        conn.commit()
    finally:
        conn.close()
    refresh_waiting_incidents_to_pending()
    process_pending_visual_validation_once()
    process_pending_incident_videos_once()
    process_pending_incidents_once()
    return jsonify({"status": "ok"})


@app.route("/api/incidents/<incident_id>/rebuild", methods=["GET", "POST"])
def api_rebuild_incident(incident_id):
    conn = get_db_connection()
    try:
        event_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM events
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()["count"]

        if not event_count:
            return (
                jsonify(
                    {
                        "status": "missing",
                        "incident_id": incident_id,
                        "message": "No events found for incident_id",
                    }
                ),
                404,
            )

        refresh_incident_record(conn, incident_id)
        conn.commit()

        incident = conn.execute(
            """
            SELECT incident_id, event_count, start_time, end_time, llm_status,
                   visual_status, video_status, updated_at
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()

        return jsonify(
            {
                "status": "rebuilt",
                "incident": dict(incident) if incident else None,
            }
        )
    finally:
        conn.close()


@app.route("/api/incidents/reconcile", methods=["GET", "POST"])
def api_reconcile_incidents():
    payload = request.get_json(silent=True) or {}

    def parse_float(value):
        if value in (None, ""):
            return None
        return float(value)

    try:
        start_time = parse_float(
            payload.get("start_time", request.args.get("start_time"))
        )
        end_time = parse_float(payload.get("end_time", request.args.get("end_time")))
        max_events = payload.get("max_events", request.args.get("max_events"))
        max_events = int(max_events) if max_events not in (None, "") else None
        dry_run_value = payload.get("dry_run", request.args.get("dry_run"))
        dry_run = (
            str(dry_run_value).lower() in {"1", "true", "yes", "on"}
            if dry_run_value is not None
            else False
        )
    except (TypeError, ValueError):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "start_time/end_time must be numeric and max_events must be an integer",
                }
            ),
            400,
        )

    conn = get_db_connection()
    try:
        result = reconcile_incidents_once(
            conn,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            dry_run=dry_run,
        )
        if not dry_run:
            conn.commit()
        return jsonify(
            {
                "status": "ok",
                "dry_run": dry_run,
                **result,
            }
        )
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>/retry-ai", methods=["POST"])
def api_retry_incident_ai(incident_id):
    try:
        result = retry_incident_llm(incident_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    if not result:
        return jsonify({"status": "missing", "incident_id": incident_id}), 404

    return jsonify({"status": "queued", **result})


@app.route("/api/events/<event_id>/override-visual", methods=["POST"])
def api_override_visual_event(event_id):
    try:
        result = override_visual_exclusion(event_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    if not result:
        return jsonify({"status": "missing", "event_id": event_id}), 404

    return jsonify({"status": "updated", **result})


@app.route("/api/events/<event_id>/remove", methods=["POST"])
def api_remove_event(event_id):
    try:
        result = remove_event_from_incident(event_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    if not result:
        return jsonify({"status": "missing", "event_id": event_id}), 404

    return jsonify({"status": "removed", **result})


@app.route("/api/events/<event_id>/shift", methods=["POST"])
def api_shift_event(event_id):
    payload = request.get_json(silent=True) or {}

    try:
        direction = int(payload.get("direction", 0))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "direction must be -1 or 1"}), 400

    if direction not in (-1, 1):
        return jsonify({"status": "error", "message": "direction must be -1 or 1"}), 400

    try:
        result = reorder_event_in_incident(event_id, direction)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    if not result:
        return jsonify({"status": "missing", "event_id": event_id}), 404

    return jsonify({"status": "shifted", **result})


@app.route("/api/incidents/editing", methods=["POST"])
def api_set_incidents_editing():
    payload = request.get_json(silent=True) or {}
    incident_ids = payload.get("incident_ids") or []
    editing = bool(payload.get("editing"))
    reprocess = bool(payload.get("reprocess", True))

    if not isinstance(incident_ids, list):
        return jsonify({"status": "error", "message": "incident_ids must be a list"}), 400

    updated_ids = set_incident_manual_editing(
        incident_ids, editing, reprocess=reprocess
    )
    return jsonify(
        {
            "status": "ok",
            "incident_ids": updated_ids,
            "editing": editing,
            "reprocess": reprocess,
        }
    )


@app.route("/video/<incident_id>")
def serve_video(incident_id):
    path = Path(VIDEO_OUTPUT_DIR) / f"{incident_id}.mp4"
    if not path.exists():
        return "Not found", 404
    return send_file(path, mimetype="video/mp4")


@app.route("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "mqtt_broker": MQTT_BROKER,
            "mqtt_port": MQTT_PORT,
            "mqtt_topic": MQTT_TOPIC,
            "mqtt_username_configured": bool(MQTT_USERNAME),
            "mqtt_tls": MQTT_TLS,
            "frigate_public_base": FRIGATE_PUBLIC_BASE,
            "frigate_media_prefix": FRIGATE_MEDIA_PREFIX,
            "frigate_clip_prefix": FRIGATE_CLIP_PREFIX,
            "frigate_vod_base": FRIGATE_VOD_BASE,
            "incident_window_seconds": INCIDENT_WINDOW_SECONDS,
            "incident_llm_idle_seconds": INCIDENT_LLM_IDLE_SECONDS,
            "incident_min_events": INCIDENT_MIN_EVENTS,
            "incident_process_below_min_events": INCIDENT_PROCESS_BELOW_MIN_EVENTS,
            "incident_min_events_prune_seconds": INCIDENT_MIN_EVENTS_PRUNE_SECONDS,
            "llm_enabled": bool(LLM_BASE_URL and LLM_MODEL),
            "llm_base_url": LLM_BASE_URL,
            "llm_model": LLM_MODEL,
            "llm_timeout": LLM_TIMEOUT,
            "incident_llm_timeout": INCIDENT_LLM_TIMEOUT,
            "incident_llm_max_retries": INCIDENT_LLM_MAX_RETRIES,
            "prompt_path": PROMPT_PATH,
            "visual_prompt_path": VISUAL_PROMPT_PATH,
            "topology_path": TOPOLOGY_PATH,
            "topology_loaded": bool(
                TOPOLOGY.get("adjacency") or TOPOLOGY.get("hard_boundaries")
            ),
            "topology_cameras": sorted(list((TOPOLOGY.get("adjacency") or {}).keys())),
            "topology_max_hops": TOPOLOGY_MAX_HOPS,
            "incident_worker_enabled": INCIDENT_WORKER_ENABLED,
            "incident_worker_interval": INCIDENT_WORKER_INTERVAL,
            "night_mode_enabled": NIGHT_MODE_ENABLED,
            "day_start_hour": DAY_START_HOUR,
            "night_start_hour": NIGHT_START_HOUR,
            "visual_validation_enabled": VISUAL_VALIDATION_ENABLED,
            "visual_matcher_mode": VISUAL_MATCHER_MODE,
            "visual_local_matcher": VISUAL_LOCAL_MATCHER,
            "visual_detector_mode": VISUAL_DETECTOR_MODE,
            "visual_detector_model": VISUAL_DETECTOR_MODEL,
            "visual_detector_confidence": VISUAL_DETECTOR_CONFIDENCE,
            "visual_embedding_model": VISUAL_EMBEDDING_MODEL,
            "visual_validation_model": VISUAL_VALIDATION_MODEL,
            "visual_validation_min_events": VISUAL_VALIDATION_MIN_EVENTS,
            "visual_validation_max_images": VISUAL_VALIDATION_MAX_IMAGES,
            "visual_validation_threshold": VISUAL_VALIDATION_THRESHOLD,
            "visual_local_match_threshold": VISUAL_LOCAL_MATCH_THRESHOLD,
            "visual_local_reject_threshold": VISUAL_LOCAL_REJECT_THRESHOLD,
            "visual_hash_size": VISUAL_HASH_SIZE,
            "video_generation_enabled": VIDEO_GENERATION_ENABLED,
            "video_output_dir": VIDEO_OUTPUT_DIR,
            "video_ffmpeg_bin": VIDEO_FFMPEG_BIN,
            "video_source_base": VIDEO_SOURCE_BASE,
            "video_min_events": VIDEO_MIN_EVENTS,
        }
    )


if __name__ == "__main__":
    configure_logging()
    init_db()
    start_mqtt()
    start_incident_worker()
    app.run(host="0.0.0.0", port=APP_PORT, threaded=True)
