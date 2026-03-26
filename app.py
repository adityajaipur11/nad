# ─────────────────────────────────────────────
# app.py — Destro Threat Dashboard · Main Flask server
# ─────────────────────────────────────────────

import os, sys, time, threading, logging, json, io, csv, random
import webbrowser
from flask import Flask, render_template, jsonify, request, redirect
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import attack_state
from attack_detector import scan_headlines_for_injection
from web_scraper.main import run_scraper
from summarizing_agent.summarizer import SummarizingAgent
from threat_analyzer import analyze_threats, _keyword_fallback

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "destro-dev-secret-change-in-prod")

# ── Browser auto-open ─────────────────────────
def open_browser():
    webbrowser.open("http://127.0.0.1:5000/dashboard")

# ── API key store ─────────────────────────────
_api_key_store = {"key": os.getenv("OPENROUTER_API_KEY", "")}
_api_key_lock  = threading.Lock()

def get_api_key() -> str:
    with _api_key_lock:
        return _api_key_store["key"]

def set_api_key(key: str) -> None:
    with _api_key_lock:
        _api_key_store["key"] = key.strip()

BASE_URL   = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
MODEL_NAME = os.getenv("OPENROUTER_MODEL",    "openai/gpt-4o-mini")


# ── Default agents ────────────────────────────
def _build_default_agents():
    return [
        {
            "id": 1, "name": "WebScraper Agent", "type": "Scraping",
            "status": "Active", "risk_score": 12, "last_activity": "Monitoring",
            "tasks_completed": 0, "icon": "🕷️",
        },
        {
            "id": 2, "name": "Threat Analyzer", "type": "Analysis",
            "status": "Idle", "risk_score": 0, "last_activity": "Waiting for scan",
            "tasks_completed": 0, "icon": "🔍",
        },
        {
            "id": 3, "name": "Injection Guard", "type": "Security",
            "status": "Active", "risk_score": 5, "last_activity": "Monitoring streams",
            "tasks_completed": 0, "icon": "🛡️",
        },
        {
            "id": 4, "name": "Summarizer Agent", "type": "AI / NLP",
            "status": "Idle", "risk_score": 0, "last_activity": "Waiting for scan",
            "tasks_completed": 0, "icon": "🤖",
        },
        {
            "id": 5, "name": "Incident Manager", "type": "Response",
            "status": "Active", "risk_score": 8, "last_activity": "2m ago",
            "tasks_completed": 0, "icon": "⚡",
        },
        {
            "id": 6, "name": "Data Pipeline", "type": "Processing",
            "status": "Idle", "risk_score": 3, "last_activity": "On demand",
            "tasks_completed": 0, "icon": "🔄",
        },
    ]


# ── In-memory cache ───────────────────────────
_cache_lock = threading.Lock()
_cache = {
    "headlines":          [],
    "threats":            [],
    "summary":            "",
    "short_description":  "",
    "injection_detected": False,
    "injection_payload":  "",
    "total_scraped":      0,
    "flagged_count":      0,
    "critical_count":     0,
    "last_scan_time":     None,
    "scan_in_progress":   False,
    "error":              None,
    "threat_statuses":    {},
    "upload_results":     [],
    "agents":             _build_default_agents(),
}

def _cache_update(u: dict) -> None:
    with _cache_lock:
        _cache.update(u)

def _cache_read() -> dict:
    with _cache_lock:
        return dict(_cache)


# ── Full scan pipeline ────────────────────────
def run_full_pipeline() -> None:
    _cache_update({"scan_in_progress": True, "error": None})

    # Mark relevant agents as busy
    with _cache_lock:
        for a in _cache["agents"]:
            if a["id"] in (1, 3):
                a["status"] = "Active"
                a["last_activity"] = "Scanning..."
            elif a["id"] == 2:
                a["status"] = "Active"
                a["last_activity"] = "Analyzing..."

    try:
        logger.info("Scraping headlines...")
        raw = run_scraper()
        if not raw:
            _cache_update({"error": "No data scraped", "scan_in_progress": False})
            return

        logger.info("Analysing %d headlines...", len(raw))
        api_key  = get_api_key()
        enriched = analyze_threats(raw, api_key, BASE_URL, MODEL_NAME)

        injected = scan_headlines_for_injection(enriched)
        state    = attack_state.snapshot()

        threats  = [h for h in enriched if h.get("is_threat")]
        critical = [h for h in enriched if h.get("severity") == "CRITICAL"]

        old_statuses = _cache_read().get("threat_statuses", {})
        statuses = {}
        for t in threats:
            key = t.get("headline", "")[:80]
            statuses[key] = old_statuses.get(key, "new")

        logger.info("Generating summary...")
        agent  = SummarizingAgent(api_key=api_key, base_url=BASE_URL, model=MODEL_NAME)
        result = agent.generate_summary(enriched)

        # Update agents after scan completes
        with _cache_lock:
            for a in _cache["agents"]:
                ts = time.strftime("%H:%M:%S")
                if a["id"] == 1:   # WebScraper
                    a["status"] = "Active"; a["tasks_completed"] += 1
                    a["last_activity"] = ts; a["risk_score"] = len(threats)
                elif a["id"] == 2:  # Threat Analyzer
                    a["status"] = "Idle"; a["tasks_completed"] += 1
                    a["last_activity"] = ts; a["risk_score"] = len(critical) * 10
                elif a["id"] == 3:  # Injection Guard
                    a["status"] = "Active"; a["tasks_completed"] += 1
                    a["last_activity"] = ts; a["risk_score"] = len(injected) * 5
                elif a["id"] == 4:  # Summarizer
                    a["status"] = "Idle"; a["tasks_completed"] += 1
                    a["last_activity"] = ts
                elif a["id"] == 5:  # Incident Manager
                    a["status"] = "Active"; a["tasks_completed"] += len(threats)
                    a["last_activity"] = ts; a["risk_score"] = min(len(threats) * 3, 99)
                elif a["id"] == 6:  # Data Pipeline
                    a["status"] = "Idle"; a["tasks_completed"] += len(enriched)
                    a["last_activity"] = ts

        _cache_update({
            "headlines":          enriched,
            "threats":            threats,
            "summary":            result.get("summary_paragraph", ""),
            "short_description":  result.get("short_description", ""),
            "injection_detected": state["injection_detected"],
            "injection_payload":  state["injection_payload"],
            "total_scraped":      len(enriched),
            "flagged_count":      len(threats),
            "critical_count":     len(critical),
            "last_scan_time":     time.strftime("%H:%M:%S"),
            "scan_in_progress":   False,
            "threat_statuses":    statuses,
        })
        logger.info(
            "Pipeline done — %d headlines, %d threats, %d critical",
            len(enriched), len(threats), len(critical),
        )

    except Exception as exc:
        logger.exception("Pipeline error: %s", exc)
        with _cache_lock:
            for a in _cache["agents"]:
                if a["last_activity"] in ("Scanning...", "Analyzing..."):
                    a["status"] = "Idle"
                    a["last_activity"] = "Error — see log"
        _cache_update({"error": str(exc), "scan_in_progress": False})


# ════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════

@app.route("/")
def landing():
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/threats")
def threats():
    return render_template("threats.html")

@app.route("/agents")
def agents():
    return render_template("agents.html")

@app.route("/settings")
def settings():
    return render_template("settings.html")

@app.route("/reports")
def reports():
    return render_template("reports.html")

@app.route("/dash")
def dash_redirect():
    return redirect("/dashboard")

@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


# ── API: status & core data ───────────────────

@app.route("/api/status")
def api_status():
    cache = _cache_read()
    state = attack_state.snapshot()
    return jsonify({
        "attack_mode":        state["attack_mode"],
        "injection_detected": cache["injection_detected"],
        "injection_payload":  cache["injection_payload"],
        "total_scraped":      cache["total_scraped"],
        "flagged_count":      cache["flagged_count"],
        "critical_count":     cache["critical_count"],
        "last_scan_time":     cache["last_scan_time"],
        "scan_in_progress":   cache["scan_in_progress"],
        "error":              cache["error"],
        "api_key_set":        bool(get_api_key()),
    })

@app.route("/api/headlines")
def api_headlines():
    cache = _cache_read()
    return jsonify({"headlines": cache["headlines"], "total": len(cache["headlines"])})

@app.route("/api/threats")
def api_threats():
    cache    = _cache_read()
    threats  = cache["threats"]
    statuses = cache.get("threat_statuses", {})
    result = []
    for t in threats:
        item = dict(t)
        key  = item.get("headline", "")[:80]
        item["status"] = statuses.get(key, "new")
        result.append(item)
    return jsonify({"threats": result, "total": len(result)})

@app.route("/api/summary")
def api_summary():
    cache = _cache_read()
    return jsonify({"summary": cache["summary"], "title": cache["short_description"]})


# ── API: scan / attack ────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    cache = _cache_read()
    if cache["scan_in_progress"]:
        return jsonify({"message": "Scan already in progress"}), 409
    threading.Thread(target=run_full_pipeline, daemon=True).start()
    return jsonify({"message": "Scan started"})

@app.route("/api/attack-mode/<state>", methods=["POST"])
def set_attack_mode(state: str):
    if state not in ("on", "off"):
        return jsonify({"error": "Use 'on' or 'off'"}), 400
    active = (state == "on")
    attack_state.set_attack_mode(active)
    if not active:
        attack_state.reset_attack()
        _cache_update({"injection_detected": False, "injection_payload": ""})
    return jsonify({"attack_mode": active})

@app.route("/api/threat-action", methods=["POST"])
def api_threat_action():
    data   = request.get_json(silent=True) or {}
    key    = (data.get("headline") or "")[:80]
    action = data.get("action")
    if action not in ("acknowledge", "dismiss", "reopen"):
        return jsonify({"error": "Invalid action"}), 400
    status_map = {"acknowledge": "acknowledged", "dismiss": "dismissed", "reopen": "new"}
    with _cache_lock:
        _cache["threat_statuses"][key] = status_map[action]
        for a in _cache["agents"]:
            if a["id"] == 5:  # Incident Manager handles threat responses
                a["tasks_completed"] += 1
                a["last_activity"] = time.strftime("%H:%M:%S")
    return jsonify({"ok": True, "status": status_map[action]})

@app.route("/api/set-key", methods=["POST"])
def api_set_key():
    data = request.get_json(silent=True) or {}
    key  = data.get("key", "").strip()
    if not key:
        return jsonify({"error": "No key provided"}), 400
    set_api_key(key)
    logger.info("API key updated via UI")
    return jsonify({"ok": True, "key_preview": f"{key[:8]}…"})

@app.route("/api/test-key", methods=["POST"])
def api_test_key():
    key = get_api_key()
    if not key:
        return jsonify({"ok": False, "error": "No API key set"}), 400
    import urllib.request as _ur
    try:
        payload = json.dumps({
            "model": MODEL_NAME,
            "messages": [{"role": "user", "content": "Say OK"}],
            "max_tokens": 5,
        }).encode()
        req = _ur.Request(
            f"{BASE_URL}/chat/completions", data=payload,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        with _ur.urlopen(req, timeout=10) as r:
            json.loads(r.read())
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ── API: incidents (threats + sample fallback) ─

@app.route("/api/incidents")
def api_incidents():
    cache    = _cache_read()
    statuses = cache.get("threat_statuses", {})
    threats  = list(cache.get("threats", []))

    if not threats:
        threats = _sample_incidents()

    result = []
    for t in threats:
        item = dict(t)
        key  = item.get("headline", "")[:80]
        item["status"] = statuses.get(key, "new")
        result.append(item)

    return jsonify({"incidents": result, "total": len(result)})

def _sample_incidents():
    return [
        {
            "headline":   "Critical RCE vulnerability in Apache Struts — unpatched systems at risk",
            "source":     "Sample / Demo",
            "severity":   "CRITICAL",
            "category":   "Vulnerability",
            "is_threat":  True,
            "affected":   "Apache Struts 2.x deployments",
            "mitigation": "Apply patch 2.5.33 immediately. Block inbound traffic on affected endpoints if patching is delayed.",
            "cve_ref":    "CVE-2024-53677",
            "attack_signal": True,
        },
        {
            "headline":   "Large-scale phishing campaign targeting Microsoft 365 users",
            "source":     "Sample / Demo",
            "severity":   "HIGH",
            "category":   "Phishing",
            "is_threat":  True,
            "affected":   "Microsoft 365 enterprise users",
            "mitigation": "Enable MFA and conditional access policies. Alert users to verify sender identity before clicking links.",
            "cve_ref":    "N/A",
            "attack_signal": True,
        },
        {
            "headline":   "Ransomware group LockBit infrastructure dismantled by international taskforce",
            "source":     "Sample / Demo",
            "severity":   "MEDIUM",
            "category":   "Ransomware",
            "is_threat":  True,
            "affected":   "Previously affected organisations",
            "mitigation": "Rotate encryption keys and passwords for exposed systems. Review backup integrity.",
            "cve_ref":    "N/A",
            "attack_signal": False,
        },
        {
            "headline":   "Supply chain attack in popular npm package affects 4 000+ projects",
            "source":     "Sample / Demo",
            "severity":   "HIGH",
            "category":   "Supply Chain",
            "is_threat":  True,
            "affected":   "Node.js / npm ecosystem",
            "mitigation": "Audit package.json for the affected package. Downgrade and run npm audit.",
            "cve_ref":    "N/A",
            "attack_signal": True,
        },
    ]


# ── API: upload ───────────────────────────────

ALLOWED_EXTENSIONS = {".csv", ".json", ".txt"}
MAX_UPLOAD_BYTES   = 5 * 1024 * 1024  # 5 MB

def _parse_upload(filename: str, content: bytes) -> list:
    ext  = os.path.splitext(filename)[1].lower()
    text = content.decode("utf-8", errors="replace")
    rows = []

    if ext == ".csv":
        try:
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                headline = (
                    row.get("headline") or row.get("title") or row.get("text") or
                    row.get("message") or row.get("content") or
                    " | ".join(str(v) for v in row.values() if v)
                )
                if headline and headline.strip():
                    rows.append({"headline": headline.strip(), "source": "Upload/CSV", "attack_signal": False})
        except Exception:
            for line in text.splitlines():
                line = line.strip()
                if line and len(line) > 5:
                    rows.append({"headline": line, "source": "Upload/CSV", "attack_signal": False})

    elif ext == ".json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            return [{"headline": f"JSON parse error: {e}", "source": "Upload/JSON", "attack_signal": False}]
        items = parsed if isinstance(parsed, list) else [parsed]
        for item in items:
            if isinstance(item, dict):
                headline = (
                    item.get("headline") or item.get("title") or item.get("text") or
                    item.get("message") or item.get("content") or
                    " | ".join(f"{k}: {v}" for k, v in item.items() if isinstance(v, str))[:120]
                )
            elif isinstance(item, str):
                headline = item
            else:
                headline = str(item)
            if headline and str(headline).strip():
                rows.append({"headline": str(headline).strip(), "source": "Upload/JSON", "attack_signal": False})

    else:  # .txt
        for line in text.splitlines():
            line = line.strip()
            if line and len(line) > 5:
                rows.append({"headline": line, "source": "Upload/TXT", "attack_signal": False})

    return rows[:500]  # cap at 500 records


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f    = request.files["file"]
    name = f.filename or "upload"
    ext  = os.path.splitext(name)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type '{ext}'. Use CSV, JSON, or TXT."}), 400

    content = f.read()
    if len(content) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "File exceeds 5 MB limit"}), 400
    if not content.strip():
        return jsonify({"error": "File is empty"}), 400

    logger.info("Upload received: %s (%d bytes)", name, len(content))

    rows     = _parse_upload(name, content)
    enriched = _keyword_fallback(rows) if rows else []
    threats  = [h for h in enriched if h.get("is_threat")]
    critical = [h for h in enriched if h.get("severity") == "CRITICAL"]

    log_lines = [
        f"📂 File: {name}  ({max(1, len(content) // 1024)} KB · {ext.upper()[1:]})",
        f"📊 Parsed {len(rows)} records",
        "─" * 44,
    ]

    if not rows:
        log_lines.append("⚠  No parseable records found in file.")
    else:
        log_lines.append(f"✓  Analysis complete — {len(threats)} threat(s) detected")
        if critical:
            log_lines.append(f"🔴 {len(critical)} CRITICAL item(s):")
            for h in critical[:5]:
                log_lines.append(f"   · {h['headline'][:80]}")
        hi = [h for h in threats if h.get("severity") == "HIGH"]
        if hi:
            log_lines.append(f"🟠 {len(hi)} HIGH severity item(s):")
            for h in hi[:3]:
                log_lines.append(f"   · {h['headline'][:80]}")
        med = [h for h in threats if h.get("severity") == "MEDIUM"]
        if med:
            log_lines.append(f"🟡 {len(med)} MEDIUM severity item(s)")
        cats = {}
        for h in threats:
            c = h.get("category", "Other")
            if c and c != "None":
                cats[c] = cats.get(c, 0) + 1
        if cats:
            top = sorted(cats.items(), key=lambda x: -x[1])[:5]
            log_lines.append("─" * 44)
            log_lines.append("📁 Categories: " + ", ".join(f"{k} ({v})" for k, v in top))
        if not threats:
            log_lines.append("✅ No threats detected — content appears clean")

    log_lines += ["─" * 44, f"⏱  Completed at {time.strftime('%H:%M:%S')}"]

    _cache_update({"upload_results": enriched})

    with _cache_lock:
        for a in _cache["agents"]:
            if a["id"] == 6:  # Data Pipeline handles uploads
                a["status"] = "Active"
                a["tasks_completed"] += len(rows)
                a["last_activity"] = time.strftime("%H:%M:%S")
                a["risk_score"] = min(len(threats) * 5, 99)

    return jsonify({
        "filename": name,
        "total":    len(rows),
        "threats":  len(threats),
        "critical": len(critical),
        "log":      log_lines,
    })


# ── API: agents ───────────────────────────────

@app.route("/api/agents")
def api_agents():
    with _cache_lock:
        agents = [dict(a) for a in _cache["agents"]]
    return jsonify({"agents": agents, "total": len(agents)})

@app.route("/api/agents/<int:agent_id>/update", methods=["POST"])
def api_agent_update(agent_id: int):
    with _cache_lock:
        for a in _cache["agents"]:
            if a["id"] == agent_id:
                statuses      = ["Active", "Active", "Active", "Idle", "Warning"]
                a["status"]        = random.choice(statuses)
                drift              = random.randint(-5, 8)
                a["risk_score"]    = max(0, min(a["risk_score"] + drift, 99))
                a["last_activity"] = time.strftime("%H:%M:%S")
                return jsonify({
                    "ok": True, "id": a["id"], "name": a["name"],
                    "status": a["status"], "risk_score": a["risk_score"],
                })
    return jsonify({"error": f"Agent {agent_id} not found"}), 404

@app.route("/api/agents/refresh", methods=["POST"])
def api_agents_refresh():
    with _cache_lock:
        for a in _cache["agents"]:
            drift = random.randint(-3, 5)
            a["risk_score"] = max(0, min(a["risk_score"] + drift, 99))
            a["last_activity"] = time.strftime("%H:%M:%S")
    return jsonify({"ok": True})


# ════════════════════════════════════════════════
#  ENTRYPOINT
# ════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("Starting Destro → http://127.0.0.1:5000/dashboard")
    threading.Timer(1.5, open_browser).start()
    app.run(debug=True, use_reloader=False, host="127.0.0.1", port=5000)
