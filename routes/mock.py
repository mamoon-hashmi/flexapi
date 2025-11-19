# routes/mock.py — 100% FINAL, TESTED & WORKING
from flask import Blueprint, request, jsonify, current_app
from bson.objectid import ObjectId
from datetime import datetime
import re

mock_bp = Blueprint('mock', __name__, url_prefix='/api/mock')

# Ye helper function ObjectId, datetime sabko JSON safe banata hai
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
        # full_path = "mamoon-c5de6b/users" ya "mamoon-c5de6b/users/123"
        parts = full_path.strip('/').split('/')
        if not parts:
            return jsonify({"error": "Invalid URL"}), 400

        project_slug = parts[0]  # mamoon-c5de6b
        endpoint_path = '/' + '/'.join(parts[1:]) if len(parts) > 1 else '/'

        # Project find karo by slug (base_url ke end mein match)
        project = projects.find_one({
            "base_url": {"$regex": f"{re.escape(project_slug)}$"}
        })

        if not project:
            return jsonify({"error": "Project not found"}), 404

        # Ab endpoints check karo
        endpoints = project.get("endpoints", [])
        matched_ep = None
        for ep in endpoints:
            if ep.get("path") == endpoint_path and request.method in ep.get("methods", []):
                matched_ep = ep
                break

        if matched_ep:
            # Delay apply karo
            delay = matched_ep.get("delay", 0)
            if delay > 0:
                import time
                time.sleep(delay / 1000)

            # Custom response
            response_data = to_serializable(matched_ep["response"])
            resp = jsonify(response_data)
            resp.status_code = matched_ep.get("status_code", 200)

            # Headers add karo
            for h in matched_ep.get("headers", []):
                resp.headers[h.get("key")] = h.get("value")

            return resp

        # Agar koi endpoint match nahi hua → default collection-based behavior
        collection_name = f"{project_slug}_{parts[1] if len(parts) > 1 else 'default'}".lower()
        collection = mongo.db[collection_name]
        doc_id = parts[2] if len(parts) > 2 else None

        # GET
        if request.method == "GET":
            if doc_id:
                try:
                    doc = collection.find_one({"_id": ObjectId(doc_id)})
                except:
                    doc = collection.find_one({"id": doc_id})
                if not doc:
                    return jsonify({"error": "Not found"}), 404
                return jsonify(to_serializable(doc))
            else:
                docs = list(collection.find().limit(50))
                return jsonify([to_serializable(d) for d in docs])

        # POST
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            data["created_at"] = datetime.utcnow()
            result = collection.insert_one(data)
            return jsonify({"_id": str(result.inserted_id), "message": "Created"}), 201

        # PUT / PATCH
        if request.method in ["PUT", "PATCH"]:
            if not doc_id:
                return jsonify({"error": "ID required"}), 400
            data = request.get_json(silent=True) or {}
            data["updated_at"] = datetime.utcnow()
            result = collection.update_one(
                {"_id": ObjectId(doc_id)},
                {"$set": data},
                upsert=False
            )
            return jsonify({"modified": result.modified_count > 0})

        # DELETE
        if request.method == "DELETE":
            if not doc_id:
                return jsonify({"error": "ID required"}), 400
            result = collection.delete_one({"_id": ObjectId(doc_id)})
            return jsonify({"deleted": result.deleted_count > 0})

        return jsonify({"message": "Welcome to MockAPI Pro!", "project": project["name"]})

    app.register_blueprint(mock_bp)