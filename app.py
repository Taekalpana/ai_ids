import os
from flask import Blueprint, request, jsonify, send_from_directory, render_template_string, current_app
from dotenv import load_dotenv
import tensorflow as tf
import numpy as np
import pandas as pd
from .suspicious_scanner import (
    scan_target,
    normalize_targets,
    scan_single_target_quick,
    scan_single_target_full,
    parse_ports_arg,
    scan_website_url,
    scan_website_batch
)

load_dotenv()

susp_bp = Blueprint('susp_bp', __name__, template_folder='static')

# ---------------- IDS model setup ----------------
MODEL_FILENAME = os.getenv("IDS_MODEL_PATH", "model.h5")
model = None
model_loaded = False
FEATURES = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes"]

def try_load_model(path):
    global model, model_loaded
    try:
        if os.path.exists(path):
            model = tf.keras.models.load_model(path)
            model_loaded = True
            print(f"Loaded IDS model from {path}")
            return True
    except Exception as e:
        print("Error loading model:", e)
    return False

# Try loading model
if not try_load_model(MODEL_FILENAME):
    alt = os.path.join(os.path.dirname(__file__), MODEL_FILENAME)
    try_load_model(alt)

if not model_loaded:
    print("No IDS model found. IDS upload endpoint will not run predictions until model.h5 is provided.")

def run_ids(file_path):
    if not model_loaded or model is None:
        return {"error": "IDS model not loaded. Put a valid model.h5 in project root or set IDS_MODEL_PATH."}
    try:
        df = pd.read_csv(file_path)
        missing = [c for c in FEATURES if c not in df.columns]
        if missing:
            return {"error": f"Missing columns required by model: {missing}"}
        X = df[FEATURES].to_numpy()
        preds = model.predict(X)
        predicted_labels = (preds > 0.5).astype(int).reshape(-1)
        malicious = int(predicted_labels.sum())
        normal = int(len(predicted_labels) - malicious)
        return {"total_records": len(predicted_labels), "malicious": malicious, "normal": normal}
    except Exception as e:
        return {"error": str(e)}

# ---------------- Flask endpoints ----------------
from flask import current_app

@susp_bp.route("/")
def index():
    static_index = os.path.join(current_app.static_folder or "", "index.html")
    if os.path.exists(static_index):
        return send_from_directory(current_app.static_folder, "index.html")
    return render_template_string("<p>Put your frontend index.html into static/ to use the UI.</p>")


@susp_bp.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    os.makedirs("uploads", exist_ok=True)
    name = file.filename or "upload.csv"
    path = os.path.join("uploads", name)
    file.save(path)
    result = run_ids(path)
    return jsonify({"IDS_Result": result})

@susp_bp.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    if not target:
        return jsonify({"error": "No target provided"}), 400
    ports_arg = request.form.get("ports", "common")
    ports = parse_ports_arg(ports_arg)
    result = scan_target(target, ports=ports)
    return jsonify(result)

@susp_bp.route("/scan_batch", methods=["POST"])
def scan_batch():
    targets_text = request.form.get("targets", "")
    if not targets_text:
        return jsonify({"error": "No targets supplied"}), 400
    mode = request.form.get("mode", "quick")
    ports = parse_ports_arg(request.form.get("ports", "common"))
    targets = normalize_targets(targets_text)
    MAX_BATCH = 40
    if len(targets) > MAX_BATCH:
        return jsonify({"error": f"Too many targets (max {MAX_BATCH})"}), 400

    from concurrent.futures import ThreadPoolExecutor, as_completed
    max_workers = min(12, max(2, len(targets)))
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {}
        for t in targets:
            if mode == "quick":
                futures[ex.submit(scan_single_target_quick, t)] = t
            else:
                futures[ex.submit(scan_single_target_full, t, ports)] = t
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"target": futures[fut], "error": str(e)})
    return jsonify({"scanned": len(results), "results": results})

# ---------------- Website scan endpoints ----------------
@susp_bp.route("/scan_website", methods=["POST"])
def scan_website():
    url = request.form.get("url")
    if not url:
        return jsonify({"error": "No url provided"}), 400
    result = scan_website_url(url)
    return jsonify(result)

@susp_bp.route("/scan_website_batch", methods=["POST"])
def scan_website_batch_endpoint():
    urls_text = request.form.get("urls", "")
    if not urls_text:
        return jsonify({"error": "No urls supplied"}), 400
    urls = normalize_targets(urls_text)
    MAX_PER_BATCH = 12
    if len(urls) > MAX_PER_BATCH:
        return jsonify({"error": f"Too many URLs per batch (max {MAX_PER_BATCH})"}), 400
    timeout = float(request.form.get("timeout", "6.0"))
    result = scan_website_batch(urls, max_concurrent=6, max_per_request=MAX_PER_BATCH, timeout=timeout)
    return jsonify(result)
