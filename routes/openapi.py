# routes/openapi.py
from flask import Blueprint, request, jsonify
from bson.objectid import ObjectId
from utils import auth_required

openapi_bp = Blueprint('openapi', __name__)

def register_routes(app, mongo, config):
    projects = mongo.db.projects
    resources = mongo.db.resources
    auth_decorator = auth_required(config.SECRET_KEY)

    @openapi_bp.route('/<project_id>/export-openapi', methods=['GET'])
    @auth_decorator
    def export_openapi(project_id):
        project = projects.find_one({'_id': ObjectId(project_id)})
        res = list(resources.find({'project_id': ObjectId(project_id)}))
        openapi = {
            'openapi': '3.0.0',
            'info': {'title': project['name'], 'description': project.get('description')},
            'paths': {}
        }
        for r in res:
            for e in r.get('endpoints', []):
                path = f"{r['path']}{e['path']}"
                if path not in openapi['paths']:
                    openapi['paths'][path] = {}
                openapi['paths'][path][e['method'].lower()] = {'responses': {str(e['status_code']): {'description': 'Mock response'}}}
        return jsonify(openapi)

    @openapi_bp.route('/<project_id>/import-openapi', methods=['POST'])
    @auth_decorator
    def import_openapi(project_id):
        data = request.json  # OpenAPI JSON
        # TODO: Parse and create resources/endpoints from data
        return jsonify({'message': 'Imported'})

    app.register_blueprint(openapi_bp, url_prefix='/api/projects')