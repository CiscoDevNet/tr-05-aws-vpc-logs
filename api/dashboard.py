from flask import Blueprint

from api.schemas import DashboardTileSchema, DashboardTileDataSchema
from api.utils import jsonify_data, get_jwt, get_json
import api.utils
from api.aws_ec2 import EC2

dashboard_api = Blueprint('dashboard', __name__)


def get_summary(auth):
    response = api.utils.get_tile_model()
    ec2 = EC2(auth)
    instances = ec2.get_instances()
    intance_total = 0
    for res in instances['Reservations']:
        intance_total += len(res['Instances'])
    subnets = ec2.get_subnets()
    vpc = ec2.get_vpcs()
    sg = ec2.get_security_groups()
    response['data'].append(api.utils.set_metric_tile_data(
        'Total EC2 Instances',
        'device-type',
        'https://console.aws.amazon.com/ec2/v2',
        intance_total
    ))
    response['data'].append(api.utils.set_metric_tile_data(
        'Total VPCs',
        'static-nat',
        'https://console.aws.amazon.com/vpc',
        len(vpc)
    ))
    response['data'].append(api.utils.set_metric_tile_data(
        'Total Subnets',
        'vpn',
        'https://console.aws.amazon.com/vpc',
        len(subnets['Subnets'])
    ))
    response['data'].append(api.utils.set_metric_tile_data(
        'Total Security Groups',
        'block',
        'https://console.aws.amazon.com/vpc',
        len(sg['SecurityGroups'])
    ))
    return response


def get_ec2_details(auth):
    data = [
        "|   |   |   |   |",
        "| - | - | - | - |",
    ]
    response = api.utils.get_tile_model()
    ec2 = EC2(auth)
    instances = ec2.get_instances()
    for res in instances['Reservations']:
        for i in res['Instances']:
            name = i['InstanceId']
            if 'Tags' in i.keys():
                for t in i['Tags']:
                    if t['Key'] == 'Name':
                        name = t['Value']
            try:
                data.append(
                    '| [' + name + '](https://console.aws.amazon.com/ec2/v2/home?region=' +
                    auth['REGION'] + '#InstanceDetails:instanceId=' + i['InstanceId'] + ') | '
                                      + i['InstanceType'] + ' | ' + i['PrivateIpAddress'] + ' | '
                                      + i['State']['Name'] + ' |')
            except:
                continue
    response['data'] = data
    return response


tile_modules = [
    ['AWS Summary',
     'metric_group',
     ['AWS'],
     'Summary of Current AWS Infrastructure',
     'Summary of Current AWS Infrastructure',
     'aws_summary',
     ['last_hour'],
     'last_hour'],
    ['EC2 Instance Details',
     'markdown',
     ['AWS'],
     'Details of currently deployed EC2 instances',
     'Details of currently deployed EC2 instances',
     'aws_ec2_details',
     ['last_hour'],
     'last_hour']
]


def get_tile_modules():
    response = []
    for t in tile_modules:
        response.append(api.utils.set_tile(t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]))
    return response


@dashboard_api.route('/tiles', methods=['POST'])
def tiles():
    try:
        auth = get_jwt()
        return jsonify_data(get_tile_modules())
    except:
        return jsonify_data([])


@dashboard_api.route('/tiles/tile', methods=['POST'])
def tile():
    _ = get_jwt()
    _ = get_json(DashboardTileSchema())
    return jsonify_data({})


@dashboard_api.route('/tiles/tile-data', methods=['POST'])
def tile_data():
    auth = get_jwt()
    req = get_json(DashboardTileDataSchema())
    req_id = req['tile_id']
    if req_id == 'aws_summary':
        return jsonify_data(get_summary(auth))
    elif req_id == 'aws_ec2_details':
        return jsonify_data(get_ec2_details(auth))
    else:
        return jsonify_data({})
