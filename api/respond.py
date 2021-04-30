from functools import partial

from flask import Blueprint, current_app
from api.aws_ec2 import AWS

from api.schemas import ObservableSchema, ActionFormParamsSchema
from api.utils import get_json, get_jwt, jsonify_data

respond_api = Blueprint('respond', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))
get_action_form_params = partial(get_json, schema=ActionFormParamsSchema())


def get_isolate(observable):
    return {
        "id": "isolate-instance",
        "title": "Isolate AWS EC2 Instance",
        "description": "[Isolate AWS EC2 Instance]\n[Supported observables: IP address]"
                       "\n\nImmediately remove all existing security groups and place in isolated group\n"
                       "with no ingress or egress permissions. Will apply tag mapping all previously\n"
                       "configured Security Groups for automated un-tagging",
        'categories': ['AWS'],
        'query-params': {
            'observable_value': observable['value'],
            'observable_type': observable['type']
        }
    }


def get_un_isolate(observable):
    return {
        "id": "un-isolate-instance",
        "title": "Un-Isolate AWS EC2 Instance",
        "description": "[Un-Isolate AWS EC2 Instance]\n[Supported observables: IP address]"
                       "\n\nImmediately remove isolation security groups and replace all previously"
                       "configured Security Groups",
        'categories': ['AWS'],
        'query-params': {
            'observable_value': observable['value'],
            'observable_type': observable['type']
        }
    }


@respond_api.route('/respond/observables', methods=['POST'])
def respond_observables():
    ob = get_observables()
    auth = get_jwt()
    ec2 = AWS(auth)
    isolate = ec2.check_response(ob[0]['value'])
    if isolate is None:
        return jsonify_data([])
    if isolate:
        return jsonify_data([get_isolate(ob[0])])
    elif not isolate:
        return jsonify_data([get_un_isolate(ob[0])])


@respond_api.route('/respond/trigger/', methods=['POST'])
def respond_trigger():
    auth = get_jwt()
    ec2 = AWS(auth)
    req = get_action_form_params()
    action = req['action-id']
    if action == 'isolate-instance':
        ec2.isolate_instance(req['observable_value'])
    if action == 'un-isolate-instance':
        ec2.un_isolate_instance(req['observable_value'])
    return jsonify_data({'status': 'success'})

