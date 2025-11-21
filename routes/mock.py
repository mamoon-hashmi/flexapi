# routes/mock.py — FINAL ULTIMATE (405 GAYA, DELETE CHALEGA!)
from flask import Blueprint, request, jsonify
from bson import ObjectId
import time

mock_bp = Blueprint('mock', __name__)

def register_routes(app, mongo, config):
    projects = mongo.db.projects

    # YE DO LINES ZAROORI HAIN — HAR METHOD ALLOWED!
    @mock_bp.route('/<slug>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    @mock_bp.route('/<slug>/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    def mock_endpoint(slug, path=''):
        # Find project by slug
        project = projects.find_one({"slug": slug})
        if not project:
            return jsonify({"error": "Project not found"}), 404

        mock_data = project.get("mockData", [])
        status_code = project.get("statusCode", 200)
        delay_ms = project.get("delay", 0)

        # Delay apply
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        # Full path with leading slash
        full_path = '/' + path if path else '/'
        path_parts = [p for p in full_path.strip('/').split('/') if p]
        resource_id = path_parts[-1] if path_parts else None

        # Helper: find item by _id
        def find_item(item_id):
            for item in mock_data:
                if str(item.get("_id")) == item_id:
                    return item
            return None

        # GET
        if request.method == "GET":
            if resource_id:
                item = find_item(resource_id)
                if item:
                    return jsonify(item), status_code
                return jsonify({"error": "Not found"}), 404
            return jsonify(mock_data), status_code

        # POST
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            if "_id" not in data:
                data["_id"] = str(ObjectId())
            data["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            mock_data.append(data)
            projects.update_one({"_id": project["_id"]}, {"$set": {"mockData": mock_data}})
            return jsonify(data), 201

        # PUT / PATCH
        if request.method in ["PUT", "PATCH"]:
            if not resource_id:
                return jsonify({"error": "ID required in URL"}), 400
            item = find_item(resource_id)
            if not item:
                return jsonify({"error": "Not found"}), 404

            update_data = request.get_json(silent=True) or {}
            item.update(update_data)
            item["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            projects.update_one({"_id": project["_id"]}, {"$set": {"mockData": mock_data}})
            return jsonify(item), 200

        # DELETE — AB YE 200 DEGA!
        if request.method == "DELETE":
            if not resource_id:
                return jsonify({"error": "ID required in URL for DELETE"}), 400

            original_len = len(mock_data)
            mock_data = [item for item in mock_data if str(item.get("_id")) != resource_id]

            if len(mock_data) == original_len:
                return jsonify({"error": "Item not found"}), 404

            projects.update_one({"_id": project["_id"]}, {"$set": {"mockData": mock_data}})
            return jsonify({"message": "Deleted successfully", "deleted_id": resource_id}), 200

        # OPTIONS (CORS ke liye)
        if request.method == "OPTIONS":
            resp = jsonify({"message": "OK"})
            resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
            resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
            return resp

        return jsonify({"project": project["name"], "method": request.method}), status_code

    # Register blueprint
    app.register_blueprint(mock_bp, url_prefix='/api/mock')