import os
import json
import sqlite3
import uuid
import threading
import time
import base64
from pathlib import Path
from collections import deque
from datetime import datetime
from flask import Flask, render_template, jsonify, send_file
import paho.mqtt.client as mqtt
import requests
import subprocess
import tempfile
import shutil

DB_PATH = os.getenv("DB_PATH", "events.db")
APP_PORT = int(os.getenv("APP_PORT", "5001"))

MQTT_BROKER = os.getenv("MQTT_BROKER", "192.168.86.252")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "frigate/reviews")
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "nodered")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "password")
MQTT_CLIENT_ID = os.getenv("MQTT_CLIENT_ID", "frigate-signal")
MQTT_TLS = os.getenv("MQTT_TLS", "false").lower() in ("1", "true", "yes", "on")

FRIGATE_PUBLIC_BASE = os.getenv("FRIGATE_PUBLIC_BASE", "https://ha.loebees.com/nvr")
FRIGATE_MEDIA_PREFIX = os.getenv("FRIGATE_MEDIA_PREFIX", "/media/frigate")
FRIGATE_CLIP_PREFIX = os.getenv("FRIGATE_CLIP_PREFIX", "")
FRIGATE_VOD_BASE = os.getenv("FRIGATE_VOD_BASE", FRIGATE_PUBLIC_BASE + "/api")

INCIDENT_WINDOW_SECONDS = int(os.getenv("INCIDENT_WINDOW_SECONDS", "30"))
INCIDENT_LLM_IDLE_SECONDS = int(os.getenv("INCIDENT_LLM_IDLE_SECONDS", "15"))

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "dummy")
LLM_MODEL = os.getenv("LLM_MODEL", "")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "20"))

TOPOLOGY_PATH = os.getenv("TOPOLOGY_PATH", "camera_topology.json")
TOPOLOGY_MAX_HOPS = int(os.getenv("TOPOLOGY_MAX_HOPS", "2"))

PROMPT_PATH = os.getenv("PROMPT_PATH", "incident_prompt.txt")

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
VISUAL_VALIDATION_MODEL = os.getenv("VISUAL_VALIDATION_MODEL", LLM_MODEL)
VISUAL_VALIDATION_MIN_EVENTS = int(os.getenv("VISUAL_VALIDATION_MIN_EVENTS", "3"))
VISUAL_VALIDATION_MAX_IMAGES = int(os.getenv("VISUAL_VALIDATION_MAX_IMAGES", "6"))
VISUAL_VALIDATION_THRESHOLD = float(os.getenv("VISUAL_VALIDATION_THRESHOLD", "0.45"))

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

Path(VIDEO_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
_worker_started = False
_worker_lock = threading.Lock()


def utc_now_iso() -> str:
    return datetime.utcnow().isoformat()


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


TOPOLOGY = load_topology()
SYSTEM_PROMPT = load_system_prompt()


def refresh_topology() -> None:
    global TOPOLOGY
    TOPOLOGY = load_topology()


def refresh_system_prompt() -> None:
    global SYSTEM_PROMPT
    SYSTEM_PROMPT = load_system_prompt()


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
            video_status TEXT,
            video_error TEXT,
            video_updated_at TEXT,
            video_path TEXT,
            video_url TEXT,
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
        "video_status": "ALTER TABLE incidents ADD COLUMN video_status TEXT",
        "video_error": "ALTER TABLE incidents ADD COLUMN video_error TEXT",
        "video_updated_at": "ALTER TABLE incidents ADD COLUMN video_updated_at TEXT",
        "video_path": "ALTER TABLE incidents ADD COLUMN video_path TEXT",
        "video_url": "ALTER TABLE incidents ADD COLUMN video_url TEXT",
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


def generate_incident_video(
    incident_id: str, events: list[dict]
) -> tuple[bool, str | None]:
    if len(events) < VIDEO_MIN_EVENTS:
        return False, "not_enough_events"

    temp_dir = Path(tempfile.mkdtemp(prefix=f"incident_video_{incident_id[:8]}_"))
    concat_file = temp_dir / "concat.txt"
    output_file = Path(VIDEO_OUTPUT_DIR) / f"{incident_id}.mp4"

    try:
        local_files = []

        for idx, event in enumerate(events):
            clip_url = build_event_clip_url(
                event.get("camera"),
                event.get("start_time"),
                event.get("end_time"),
            )
            if not clip_url:
                continue

            local_path = temp_dir / f"clip_{idx}.mp4"
            if download_clip(clip_url, local_path):
                local_files.append(local_path)

        if len(local_files) < VIDEO_MIN_EVENTS:
            return False, "download_failed"

        with concat_file.open("w", encoding="utf-8") as f:
            for path in local_files:
                f.write(f"file '{path.resolve()}'\n")

        cmd = [
            VIDEO_FFMPEG_BIN,
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat_file),
            "-vf",
            "scale=1280:-2",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "23",
            "-c:a",
            "aac",
            str(output_file),
        ]

        print("[VIDEO] running:", " ".join(cmd))
        subprocess.run(cmd, check=True, capture_output=True, text=True)

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


def call_visual_validation(
    anchor_event: dict, candidate_events: list[dict]
) -> dict | None:
    if not LLM_BASE_URL or not VISUAL_VALIDATION_MODEL:
        return None

    if not anchor_event.get("thumb_url"):
        return None

    anchor_data_url = fetch_image_as_data_url(
        anchor_event["thumb_url"], anchor_event.get("thumb_path")
    )
    if not anchor_data_url:
        return None

    prepared_candidates = []
    for event in candidate_events[:VISUAL_VALIDATION_MAX_IMAGES]:
        if not event.get("thumb_url"):
            continue
        data_url = fetch_image_as_data_url(event["thumb_url"], event.get("thumb_path"))
        if not data_url:
            continue
        prepared_candidates.append(
            {
                "event_id": event["id"],
                "camera": event.get("camera"),
                "time": event.get("start_time"),
                "image_data_url": data_url,
            }
        )

    if not prepared_candidates:
        return None

    system_prompt = (
        "You are validating whether surveillance event images belong to the same subject. "
        "Use the anchor image as the reference subject. "
        "For each candidate image, decide whether it likely shows the same subject as the anchor. "
        "Be conservative. If uncertain due to angle, distance, or occlusion, prefer low confidence rather than a false match. "
        "Return ONLY raw JSON with this format: "
        '{"matches":[{"event_id":"...","match":true,"confidence":0.0}],"overall_confidence":0.0}'
    )

    content = [
        {
            "type": "text",
            "text": (
                "Anchor image first. Then candidate images. "
                "Evaluate whether each candidate likely shows the same subject as the anchor. "
                "Confidence must be 0.0 to 1.0."
            ),
        },
        {
            "type": "text",
            "text": f"Anchor event_id={anchor_event['id']} camera={anchor_event.get('camera')}",
        },
        {"type": "image_url", "image_url": {"url": anchor_data_url}},
    ]

    for candidate in prepared_candidates:
        content.append(
            {
                "type": "text",
                "text": f"Candidate event_id={candidate['event_id']} camera={candidate.get('camera')}",
            }
        )
        content.append(
            {
                "type": "image_url",
                "image_url": {"url": candidate["image_data_url"]},
            }
        )

    try:
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
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": content},
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

        parsed = extract_json_from_text(message_content)

        matches = parsed.get("matches", []) or []
        overall_confidence = parsed.get("overall_confidence")
        try:
            overall_confidence = (
                float(overall_confidence) if overall_confidence is not None else None
            )
        except Exception:
            overall_confidence = None

        normalized = []
        for item in matches:
            try:
                confidence = float(item.get("confidence", 0))
            except Exception:
                confidence = 0.0
            normalized.append(
                {
                    "event_id": item.get("event_id"),
                    "match": bool(item.get("match")),
                    "confidence": confidence,
                }
            )

        return {
            "matches": normalized,
            "overall_confidence": overall_confidence,
        }
    except Exception as e:
        print(f"[VISUAL] validation failed: {e}")
        return None


def call_incident_llm(
    events_payload: list[dict], cameras: list[str], labels: list[str], severity: str
) -> dict | None:
    if not LLM_BASE_URL or not LLM_MODEL:
        return None

    ordered_events = sorted(
        events_payload, key=lambda e: float(e.get("start_time") or 0)
    )

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

    try:
        print(f"[LLM] calling {LLM_BASE_URL} model={LLM_MODEL}")
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
            timeout=LLM_TIMEOUT,
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
        print("LLM incident synthesis failed:", e)
        return None


def incident_is_ready_for_llm(
    event_rows: list[sqlite3.Row], visual_status: str | None
) -> tuple[bool, str]:
    if not event_rows:
        return False, "no_events"

    if visual_validation_should_run(event_rows):
        if visual_status not in ("ready", "skipped", "error"):
            return False, "waiting_for_visual_validation"

    for row in event_rows:
        if row["metadata_title"] or row["metadata_summary"] or row["metadata_scene"]:
            return True, "event_genai_present"

    latest_update = max((row["updated_at"] or "" for row in event_rows), default="")
    if latest_update:
        try:
            latest_dt = datetime.fromisoformat(latest_update)
            idle_seconds = (datetime.utcnow() - latest_dt).total_seconds()
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
               visual_match, visual_confidence,
               zones_json, objects_json, updated_at
        FROM events
        WHERE incident_id = ?
        ORDER BY start_time ASC, updated_at ASC
        """,
        (incident_id,),
    ).fetchall()

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
               video_status, video_error, video_updated_at, video_path, video_url
        FROM incidents
        WHERE incident_id = ?
        """,
        (incident_id,),
    ).fetchone()

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
            source_updated_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            source_updated_at,
            created_at,
            utc_now_iso(),
        ),
    )


def refresh_waiting_incidents_to_pending() -> None:
    conn = get_db_connection()
    try:
        waiting_rows = conn.execute(
            """
            SELECT incident_id
            FROM incidents
            WHERE llm_status = 'waiting'
                OR visual_status = 'pending'
                OR video_status IS NULL
                OR video_status = 'pending'
            """
        ).fetchall()

        for row in waiting_rows:
            refresh_incident_record(conn, row["incident_id"])

        conn.commit()
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
            ORDER BY updated_at ASC
            LIMIT 5
            """
        ).fetchall()

        for incident in incidents_to_process:
            incident_id = incident["incident_id"]

            try:
                rows = conn.execute(
                    """
                    SELECT id, camera, start_time, thumb_path, updated_at, visual_match, visual_confidence
                    FROM events
                    WHERE incident_id = ?
                    ORDER BY start_time ASC, updated_at ASC
                    """,
                    (incident_id,),
                ).fetchall()

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
                            "thumb_path": row["thumb_path"],
                            "thumb_url": thumb_url,
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
                candidate_events = [
                    e for e in events_payload if e["id"] != anchor_event["id"]
                ]

                result = call_visual_validation(anchor_event, candidate_events)

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
                    continue

                conn.execute(
                    """
                    UPDATE events
                    SET visual_match = 1,
                        visual_confidence = 1.0
                    WHERE id = ?
                    """,
                    (anchor_event["id"],),
                )

                match_map = {
                    item["event_id"]: item for item in result.get("matches", [])
                }

                for event in candidate_events:
                    item = match_map.get(event["id"])
                    if not item:
                        match = 0
                        confidence = 0.0
                    else:
                        confidence = float(item.get("confidence", 0.0))
                        match = (
                            1
                            if (
                                item.get("match")
                                and confidence >= VISUAL_VALIDATION_THRESHOLD
                            )
                            else 0
                        )

                    conn.execute(
                        """
                        UPDATE events
                        SET visual_match = ?,
                            visual_confidence = ?
                        WHERE id = ?
                        """,
                        (
                            match,
                            confidence,
                            event["id"],
                        ),
                    )

                conn.execute(
                    """
                    UPDATE incidents
                    SET visual_status = 'ready',
                        visual_error = NULL,
                        visual_updated_at = ?,
                        visual_confidence = ?,
                        updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        utc_now_iso(),
                        result.get("overall_confidence"),
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
            ORDER BY updated_at ASC
            LIMIT 10
            """
        ).fetchall()

        for incident in incidents_to_process:
            incident_id = incident["incident_id"]

            try:
                event_rows = conn.execute(
                    """
                    SELECT id, camera, start_time, end_time, visual_match
                    FROM events
                    WHERE incident_id = ?
                    ORDER BY start_time ASC, updated_at ASC
                    """,
                    (incident_id,),
                ).fetchall()

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
                           visual_match, visual_confidence,
                           zones_json, objects_json, updated_at
                    FROM events
                    WHERE incident_id = ?
                    ORDER BY start_time ASC, updated_at ASC
                    """,
                    (incident_id,),
                ).fetchall()

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
                    conn.execute(
                        """
                        UPDATE incidents
                        SET llm_status = 'error',
                            llm_error = 'LLM synthesis failed or returned invalid JSON',
                            updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
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
               visual_match, visual_confidence,
               zones_json, objects_json, updated_at
        FROM events
        ORDER BY updated_at DESC
        LIMIT 100
        """
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
        ORDER BY updated_at DESC
        LIMIT 50
        """
    ).fetchall()

    results = []
    for incident in incident_rows:
        event_rows = conn.execute(
            """
            SELECT id, incident_id, event_type, camera, start_time, end_time, frigate_severity,
                   label, score, severity, thumb_path,
                   metadata_title, metadata_summary, metadata_scene,
                   metadata_confidence, metadata_threat_level,
                   visual_match, visual_confidence,
                   zones_json, objects_json, updated_at
            FROM events
            WHERE incident_id = ?
            ORDER BY start_time ASC, updated_at ASC
            """,
            (incident["incident_id"],),
        ).fetchall()

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
            all_events_payload.append(item)

            if incident["visual_status"] == "ready" and row["visual_match"] == 0:
                continue

            visible_events_payload.append(item)

        visible_cameras = []
        for ev in visible_events_payload:
            if ev["camera"] not in visible_cameras:
                visible_cameras.append(ev["camera"])

        horizontal_path = [
            {
                "camera": ev["camera"],
                "time": ev["start_time"],
                "label": ev["label"],
                "event_type": ev["event_type"],
            }
            for ev in visible_events_payload
        ]

        excluded_event_count = max(
            0, len(all_events_payload) - len(visible_events_payload)
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
    return jsonify(
        {
            "status": "reloaded",
            "prompt_path": PROMPT_PATH,
            "length": len(SYSTEM_PROMPT),
        }
    )


@app.route("/api/worker/run", methods=["GET", "POST"])
def api_worker_run():
    refresh_waiting_incidents_to_pending()
    process_pending_visual_validation_once()
    process_pending_incident_videos_once()
    process_pending_incidents_once()
    return jsonify({"status": "ok"})


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
            "llm_enabled": bool(LLM_BASE_URL and LLM_MODEL),
            "llm_base_url": LLM_BASE_URL,
            "llm_model": LLM_MODEL,
            "prompt_path": PROMPT_PATH,
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
            "visual_validation_model": VISUAL_VALIDATION_MODEL,
            "visual_validation_min_events": VISUAL_VALIDATION_MIN_EVENTS,
            "visual_validation_max_images": VISUAL_VALIDATION_MAX_IMAGES,
            "visual_validation_threshold": VISUAL_VALIDATION_THRESHOLD,
            "video_generation_enabled": VIDEO_GENERATION_ENABLED,
            "video_output_dir": VIDEO_OUTPUT_DIR,
            "video_ffmpeg_bin": VIDEO_FFMPEG_BIN,
            "video_source_base": VIDEO_SOURCE_BASE,
            "video_min_events": VIDEO_MIN_EVENTS,
        }
    )


if __name__ == "__main__":
    init_db()
    start_mqtt()
    start_incident_worker()
    app.run(host="0.0.0.0", port=APP_PORT, threaded=True)
