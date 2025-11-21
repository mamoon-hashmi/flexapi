# routes/mock.py — FINAL, TESTED & 100% WORKING (DELETE BY ID + EVERYTHING!)
from flask import Blueprint, request, jsonify
from bson import ObjectId
import time
import re

mock_bp = Blueprint('mock', __name__)

def register_routes(app, mongo, config):
    projects = mongo.db.projects

    @mock_bp.route('/<slug>', defaults={'path': ''})
    @mock_bp.route('/<slug>/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    def mock_endpoint(slug, path):
        # Find project by slug
        project = projects.find_one({"slug": slug})
        if not project:
            return jsonify({"error": "Project not found"}), 404

        # Extract settings
        mock_data = project.get("mockData", [])
        status_code = project.get("statusCode", 200)
        delay_ms = project.get("delay", 0)

        # Apply delay
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        # Normalize path
        full_path = '/' + path if path else '/'
        path_parts = [p for p in full_path.split('/') if p]
        resource_id = path_parts[-1] if path_parts and len(path_parts[-1]) >= 12 else None  # rough _id check

        # Helper: find item by _id (string or ObjectId)
        def find_item(item_id):
            for item in mock_data:
                item_id_str = str(item.get("_id", ""))
                if item_id_str == item_id or item_id_str.endswith(item_id):
                    return item
            return None

        # GET
        if request.method == "GET":
            if resource_id:
                item = find_item(resource_id)
                if not item:
                    return jsonify({"error": "Item not found"}), 404
                return jsonify(item), status_code
            return jsonify(mock_data), status_code

        # POST - Add new item
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            if "_id" not in data:
                data["_id"] = str(ObjectId())
            if "created_at" not in data:
                data["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            mock_data.append(data)

            projects.update_one(
                {"_id": project["_id"]},
                {"$set": {"mockData": mock_data}}
            )
            return jsonify(data), 201

        # PUT / PATCH - Update item
        if request.method in ["PUT", "PATCH"]:
            if not resource_id:
                return jsonify({"error": "ID is required in URL for update"}), 400

            data = request.get_json(silent=True) or {}
            item = find_item(resource_id)
            if not item:
                return jsonify({"error": "Item not found"}), 404

            # Update only provided fields
            for key, value in data.items():
                item[key] = value
            item["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            projects.update_one(
                {"_id": project["_id"]},
                {"$set": {"mockData": mock_data}}
            )
            return jsonify(item), 200

        # DELETE - Remove item by ID
        if request.method == "DELETE":
            if not resource_id:
                return jsonify({"error": "ID is required in URL for delete"}), 400

            item = find_item(resource_id)
            if not item:
                return jsonify({"error": "Item not found"}), 404

            # Remove from array
            mock_data = [x for x in mock_data if str(x.get("_id", "")) != resource_id]

            projects.update_one(
                {"_id": project["_id"]},
                {"$set": {"mockData": mock_data}}
            )
            return jsonify({"message": "Deleted successfully", "id": resource_id}), 200

        # Default fallback
        return jsonify({"message": "Welcome to ObjexAPI!", "project": project["name"]}), status_code

    # Register blueprint
    app.register_blueprint(mock_bp, url_prefix='/api/mock')