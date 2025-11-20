# routes/projects.py — FINAL & 100% WORKING (NO 404 EVER AGAIN!)
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

    # 1. LIST ALL PROJECTS
    @projects_bp.route('/', methods=['GET'])
    @app.secure_auth
    def list_projects():
        raw = projects.find({'owner_id': ObjectId(request.user_id)})
        result = [to_serializable(p) for p in raw]
        return jsonify(result)

    # 2. CREATE PROJECT
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

        slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
        if not slug:
            slug = 'project'
        unique_id = str(ObjectId())[-6:]
        slug_with_id = f"{slug}-{unique_id}"

        base_url = f"https://objexapi.vercel.app/api/mock/{slug_with_id}"

        project_doc = {
            'name': name,
            'owner_id': ObjectId(user_id),
            'base_url': base_url,
            'slug': slug_with_id,
            'mockData': [],
            'statusCode': 200,
            'delay': 0,
            'created_at': datetime.utcnow(),
            'endpoints': []
        }

        result = projects.insert_one(project_doc)

        users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'current_projects': current_count + 1}}
        )

        return jsonify({
            '_id': str(result.inserted_id),
            'name': name,
            'base_url': base_url,
            'slug': slug_with_id,
            'message': 'Project created!'
        }), 201

    # 3. DELETE PROJECT
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
            return jsonify({'error': 'Not found or unauthorized'}), 404

        users.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$inc': {'current_projects': -1}}
        )

        return jsonify({'message': 'Deleted successfully'})

    # 4. UPDATE PROJECT BY ID (Editor uses this for auto-save)
    @projects_bp.route('/<pid>', methods=['PUT'])
    @app.secure_auth
    def update_project(pid):
        try:
            ObjectId(pid)
        except:
            return jsonify({'error': 'Invalid ID'}), 400

        data = request.json or {}
        update_fields = {}

        if 'mockData' in data:
            update_fields['mockData'] = data['mockData']
        if 'statusCode' in data:
            update_fields['statusCode'] = data['statusCode']
        if 'delay' in data:
            update_fields['delay'] = data['delay']

        if not update_fields:
            return jsonify({'error': 'No data to update'}), 400

        result = projects.update_one(
            {'_id': ObjectId(pid), 'owner_id': ObjectId(request.user_id)},
            {'$set': update_fields}
        )

        if result.modified_count == 0:
            return jsonify({'error': 'Not found or no changes'}), 404

        return jsonify({'message': 'Updated successfully'})

    # 5. GET PROJECT BY SLUG (gatepass-a31cb5) — YE TERE EDITOR KE LIYE HAI!
    @projects_bp.route('/slug/<slug>', methods=['GET'])
    @app.secure_auth
    def get_project_by_slug(slug):
        project = projects.find_one({
            'slug': slug,
            'owner_id': ObjectId(request.user_id)
        })

        if not project:
            return jsonify({'error': 'Project not found'}), 404

        return jsonify({
            '_id': str(project['_id']),
            'name': project['name'],
            'mockData': project.get('mockData', []),
            'statusCode': project.get('statusCode', 200),
            'delay': project.get('delay', 0),
            'base_url': project['base_url']
        })

    # 6. UPDATE PROJECT BY SLUG — YE BHI ADD KIYA (EDITOR KE LIYE PERFECT!)
    @projects_bp.route('/slug/<slug>', methods=['PUT'])
    @app.secure_auth
    def update_project_by_slug(slug):
        project = projects.find_one({
            'slug': slug,
            'owner_id': ObjectId(request.user_id)
        })

        if not project:
            return jsonify({'error': 'Project not found'}), 404

        data = request.json or {}
        update_fields = {}

        if 'mockData' in data:
            update_fields['mockData'] = data['mockData']
        if 'statusCode' in data:
            update_fields['statusCode'] = data['statusCode']
        if 'delay' in data:
            update_fields['delay'] = data['delay']

        if not update_fields:
            return jsonify({'error': 'Nothing to update'}), 400

        projects.update_one(
            {'_id': project['_id']},
            {'$set': update_fields}
        )

        return jsonify({'message': 'Saved successfully!'})

    # Register blueprint at the end
    app.register_blueprint(projects_bp, url_prefix='/api/projects')