# routes/resources.py
from flask import Blueprint, request, jsonify
from bson.objectid import ObjectId
from datetime import datetime
from utils import auth_required

resources_bp = Blueprint('resources', __name__)

def register_routes(app, mongo, config):
    resources = mongo.db.resources
    mock_data = mongo.db.mock_data
    auth_decorator = auth_required(config.SECRET_KEY)

    @resources_bp.route('/<project_id>/resources', methods=['GET'])
    @auth_decorator
    def list_resources(project_id):
        res = list(resources.find({'project_id': ObjectId(project_id)}))
        for r in res:
            r['_id'] = str(r['_id'])
            r['project_id'] = str(r['project_id'])
        return jsonify(res)

    @resources_bp.route('/<project_id>/resources', methods=['POST'])
    @auth_decorator
    def create_resource(project_id):
        data = request.json
        resource_id = resources.insert_one({
            'project_id': ObjectId(project_id),
            'name': data['name'],
            'path': data['path'],
            'schema_definition': data.get('schema_definition', {}),
            'endpoints': data.get('endpoints', []),
            'created_at': datetime.utcnow()
        }).inserted_id
        return jsonify({'_id': str(resource_id)})

    @resources_bp.route('/<project_id>/resources/<resource_id>', methods=['PUT'])
    @auth_decorator
    def update_resource(project_id, resource_id):
        data = request.json
        resources.update_one({'_id': ObjectId(resource_id), 'project_id': ObjectId(project_id)}, {'$set': data})
        return jsonify({'message': 'Updated'})

    @resources_bp.route('/<project_id>/resources/<resource_id>', methods=['DELETE'])
    @auth_decorator
    def delete_resource(project_id, resource_id):
        resources.delete_one({'_id': ObjectId(resource_id), 'project_id': ObjectId(project_id)})
        mock_data.delete_many({'resource_id': ObjectId(resource_id)})
        return jsonify({'message': 'Deleted'})

    app.register_blueprint(resources_bp, url_prefix='/api/projects')