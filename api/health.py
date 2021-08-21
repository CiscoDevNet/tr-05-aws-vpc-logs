from flask import Blueprint
from api.aws_relay import VPC

from api.utils import get_jwt, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    auth = get_jwt()
    ec2 = VPC(auth)
    return jsonify_data({'status': 'ok'})
