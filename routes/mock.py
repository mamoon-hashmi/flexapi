# routes/mock.py — 100% FINAL, TESTED & WORKING (Direct ID + Trailing Slash Support)
from flask import Blueprint, request, jsonify
from bson.objectid import ObjectId, InvalidId
from datetime import datetime
import re
import time

mock_bp = Blueprint('mock', __name__, url_prefix='/api/mock')

# JSON-safe converter (ObjectId, datetime → string)
def to_serializable(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_serializable(i) for i in obj]
    return obj

def register_routes(app, mongo, config):
    projects = mongo.db.projects

    @mock_bp.route('/<path:full_path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    def mock_endpoint(full_path):
        # Remove empty parts → handles trailing slash perfectly
        parts = [p for p in full_path.strip('/').split('/') if p]
        if not parts:
            return jsonify({"error": "Invalid URL"}), 400

        project_slug = parts[0]

        # Find project by slug
        project = projects.find_one({
            "base_url": {"$regex": f"{re.escape(project_slug)}$"}
        })
        if not project:
            return jsonify({"error": "Project not found"}), 404

        # Custom endpoints (keep your existing logic)
        endpoint_path = '/' + '/'.join(parts[1:]) if len(parts) > 1 else '/'
        matched_ep = None
        for ep in project.get("endpoints", []):
            if ep.get("path") == endpoint_path and request.method in ep.get("methods", []):
                matched_ep = ep
                break

        if matched_ep:
            delay = matched_ep.get("delay", 0)
            if delay > 0:
                time.sleep(delay / 1000)
            resp = jsonify(to_serializable(matched_ep["response"]))
            resp.status_code = matched_ep.get("status_code", 200)
            for h in matched_ep.get("headers", []):
                resp.headers[h.get("key")] = h.get("value")
            return resp

        # ———————————— NEW SMART COLLECTION LOGIC ————————————
        # Case 1: Direct ID → /mamoon-c5de6b/64f3... (YOUR MAIN CASE)
        if len(parts) == 2:
            collection = mongo.db[f"{project_slug}_default".lower()]
            doc_id = parts[1]

        # Case 2: Resource + ID → /mamoon-c5de6b/users/64f3...
        elif len(parts) >= 3:
            collection = mongo.db[f"{project_slug}_{parts[1]}".lower()]
            doc_id = parts[2]

        # Case 3: Only project slug → list default collection
        else:
            collection = mongo.db[f"{project_slug}_default".lower()]
            doc_id = None

        # ====================== HTTP METHODS ======================
        if request.method == "GET":
            if doc_id:
                try:
                    doc = collection.find_one({"_id": ObjectId(doc_id)})
                except InvalidId:
                    doc = collection.find_one({"id": doc_id})
                if not doc:
                    return jsonify({"error": "Not found"}), 404
                return jsonify(to_serializable(doc))
            else:
                docs = list(collection.find().limit(50))
                return jsonify([to_serializable(d) for d in docs])

        elif request.method == "POST":
            data = request.get_json(silent=True) or {}
            data["created_at"] = datetime.utcnow()
            result = collection.insert_one(data)
            return jsonify({"_id": str(result.inserted_id), "message": "Created"}), 201

        elif request.method in ["PUT", "PATCH"]:
            if not doc_id:
                return jsonify({"error": "ID required"}), 400
            data = request.get_json(silent=True) or {}
            data["updated_at"] = datetime.utcnow()
            try:
                result = collection.update_one(
                    {"_id": ObjectId(doc_id)},
                    {"$set": data},
                    upsert=False
                )
            except InvalidId:
                result = collection.update_one(
                    {"id": doc_id},
                    {"$set": data},
                    upsert=False
                )
            return jsonify({"modified": result.modified_count > 0})

        elif request.method == "DELETE":
            if not doc_id:
                return jsonify({"error": "ID required"}), 400

            try:
                result = collection.delete_one({"_id": ObjectId(doc_id)})
            except InvalidId:
                result = collection.delete_one({"id": doc_id})

            if result.deleted_count:
                return jsonify({"deleted": True, "id": doc_id}), 200
            else:
                return jsonify({"error": "Not found"}), 404

        # Default welcome message
        return jsonify({
            "message": "Welcome to MockAPI Pro!",
            "project": project.get("name"),
            "tip": "Use /project-slug/ID to delete directly"
        })

    app.register_blueprint(mock_bp)