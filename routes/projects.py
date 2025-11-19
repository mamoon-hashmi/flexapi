# routes/projects.py — 100% FIXED & FINAL (NO MORE 500 ERROR)
from flask import Blueprint, request, jsonify
from bson.objectid import ObjectId
from datetime import datetime
import re

projects_bp = Blueprint('projects', __name__)

def register_routes(app, mongo, config):
    projects = mongo.db.projects
    users = mongo.db.users

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

    @projects_bp.route('/', methods=['GET'])
    @app.secure_auth
    def list_projects():
        raw = projects.find({'owner_id': ObjectId(request.user_id)})
        result = [to_serializable(p) for p in raw]
        return jsonify(result)

    @projects_bp.route('/', methods=['POST'])
    @app.secure_auth
    def create_project():
        user_id = request.user_id
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        max_allowed = user.get('max_projects', 2)
        current_count = projects.count_documents({'owner_id': ObjectId(user_id)})

        if current_count >= max_allowed:
            return jsonify({
                'error': 'Limit reached',
                'message': 'Free plan allows only 2 projects.',
                'limit_reached': True
            }), 403

        data = request.json or {}
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'Project name is required'}), 400

        # Slug banao — bilkul safe
        slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
        if not slug:
            slug = 'project'
        unique_id = str(ObjectId())[-6:]
        slug_with_id = f"{slug}-{unique_id}"

        # AB YE LINE HAMESHA DEFINE HOGI — KOI ERROR NAHI!
        base_url = f"https://objexapi.vercel.app/api/mock/{slug_with_id}"

        project_doc = {
            'name': name,
            'owner_id': ObjectId(user_id),
            'base_url': base_url,
            'created_at': datetime.utcnow(),
            'endpoints': []
        }

        result = projects.insert_one(project_doc)

        # Update user's current_projects count
        users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'current_projects': current_count + 1}}
        )

        return jsonify({
            '_id': str(result.inserted_id),
            'name': name,
            'base_url': base_url,
            'message': 'Project created successfully!'
        }), 201

    @projects_bp.route('/<pid>', methods=['DELETE'])
    @app.secure_auth
    def delete_project(pid):
        try:
            project_oid = ObjectId(pid)
        except:
            return jsonify({'error': 'Invalid project ID'}), 400

        result = projects.delete_one({
            '_id': project_oid,
            'owner_id': ObjectId(request.user_id)
        })

        if result.deleted_count == 0:
            return jsonify({'error': 'Project not found or unauthorized'}), 404

        users.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$inc': {'current_projects': -1}}
        )

        return jsonify({'message': 'Project deleted successfully'})

    app.register_blueprint(projects_bp, url_prefix='/api/projects')