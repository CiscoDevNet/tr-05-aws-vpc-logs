from flask import Blueprint
from datetime import datetime, timedelta
from api.schemas import DashboardTileSchema, DashboardTileDataSchema
from api.utils import jsonify_data, get_jwt, get_json
import api.utils
from api.aws_relay import AWS, VPC


dashboard_api = Blueprint('dashboard', __name__)


def get_flows(auth, delta):
    allowed = 0
    allowed_in = 0
    allowed_out = 0
    blocked = 0
    blocked_in = 0
    blocked_out = 0
    vpc = VPC(auth)
    vpc.get_flows(None)
    for event in vpc.events:
        split = event['message'].split(' ')
        if split[3] == '-' or split[4] == '-':
            continue
        if split[12] == 'REJECT':
            blocked += 1
            if vpc.check_local(split[3]):
                blocked_in += 1
            else:
                blocked_out += 1
        else:
            allowed += 1
            if vpc.check_local(split[3]):
                allowed_in += 1
            else:
                allowed_out += 1
    return [[allowed_in, blocked_in], [allowed_out, blocked_out]]


def get_flow_tile(auth, delta):
    response = api.utils.get_tile_model()
    flow_metrics = get_flows(auth, delta)
    rings = ['Ingress', 'Egress']
    tags = ['Allowed', 'Blocked']
    response.update({'labels': [rings, tags]})
    response['data'] = api.utils.set_donut_tile_data(rings, tags, flow_metrics)
    return response


def get_ec2_summary(ec2):
    instances = ec2.get_instances()
    intance_total = 0
    for res in instances['Reservations']:
        intance_total += len(res['Instances'])
    return api.utils.set_metric_tile_data(
        'Total EC2 Instances',
        'device-type',
        'https://console.aws.amazon.com/ec2/v2',
        intance_total
    )


def get_vpc_summary(ec2):
    vpc = ec2.get_vpcs()
    return api.utils.set_metric_tile_data(
        'Total VPCs',
        'static-nat',
        'https://console.aws.amazon.com/vpc',
        len(vpc)
    )


def get_subnet_summary(ec2):
    subnets = ec2.get_subnets()
    return api.utils.set_metric_tile_data(
        'Total Subnets',
        'vpn',
        'https://console.aws.amazon.com/vpc',
        len(subnets['Subnets'])
    )


def get_sg_summary(ec2):
    sg = ec2.get_security_groups()
    return api.utils.set_metric_tile_data(
        'Total Security Groups',
        'block',
        'https://console.aws.amazon.com/vpc',
        len(sg['SecurityGroups'])
    )


def get_http_summary(ec2):
    apiv2 = ec2.get_client('apigatewayv2')
    http_gw = apiv2.get_apis()
    return api.utils.set_metric_tile_data(
        'HTTP Gateways',
        'view-metadata',
        'https://console.aws.amazon.com/apigateway/main/apis?region=' + ec2.config.region_name,
        len(http_gw['Items'])
    )


def get_rest_summary(ec2):
    apiv1 = ec2.get_client('apigateway')
    rest_gw = apiv1.get_rest_apis()
    return api.utils.set_metric_tile_data(
        'REST Gateways',
        'view-metadata',
        'https://console.aws.amazon.com/apigateway/main/apis?region=' + ec2.config.region_name,
        len(rest_gw['items'])
    )


def get_s3_summary(aws):
    s3 = aws.get_s3_client()
    buckets = s3.list_buckets()
    return api.utils.set_metric_tile_data(
        'S3 Buckets',
        'object',
        'https://s3.console.aws.amazon.com/s3/home?region=' + aws.config.region_name,
        len(buckets['Buckets'])
    )


def check_timestamp(days, check):
    end_timestamp = int(datetime.timestamp(datetime.now() + timedelta(days=-days)))
    timestamp = datetime.timestamp(datetime.strptime(
        check.split('+')[0], "%Y-%m-%dT%H:%M:%S"))
    if timestamp < end_timestamp:
        return True
    else:
        return False


def get_iam_users(aws, role):
    resp = {
        'total_users': 0,
        'api_users': 0,
        'reg_users': 0,
        'missing_mfa': 0,
        'password_over': 0,
        'last_login': 0,
        'access_key_over': 0,
        'access_key_used': 0,
        'active_access_keys': 0,
    }
    iam = aws.get_client('iam')
    account_bytes = iam.get_credential_report()
    accounts = account_bytes['Content'].decode("utf-8").split('\n')
    header = accounts[0].split(',')
    for a in accounts[1:]:
        data = {}
        resp['total_users'] += 1
        a_items = a.split(',')
        for h in range(len(header)):
            data.update({header[h]: a_items[h]})
        if data['password_enabled'] != 'false':
            resp['reg_users'] += 1
            try:
                if check_timestamp(180, data['password_last_used']):
                    resp['last_login'] += 1
            except:
                resp['last_login'] += 1
            if data['password_enabled'] != 'not_supported':
                if check_timestamp(180, data['password_last_changed']):
                    resp['password_over'] += 1
            if data['mfa_active'] == 'false':
                resp['missing_mfa'] += 1
        else:
            resp['api_users'] += 1
        if data['access_key_1_active'] == 'true':
            resp['active_access_keys'] += 1
            if check_timestamp(180, data['access_key_1_last_rotated']):
                resp['access_key_over'] += 1
            try:
                if check_timestamp(180, data['access_key_1_last_used']):
                    resp['access_key_used'] += 1
            except:
                resp['access_key_used'] += 1
        if data['access_key_2_active'] == 'true':
            resp['active_access_keys'] += 1
            if check_timestamp(180, data['access_key_2_last_rotated']):
                resp['access_key_over'] += 1
            try:
                if check_timestamp(180, data['access_key_2_last_used']):
                    resp['access_key_used'] += 1
            except:
                resp['access_key_used'] += 1
    if role == 'user':
        return [
            resp['reg_users'],
            resp['password_over'],
            resp['last_login'],
            resp['missing_mfa']
        ]
    else:
        return [
            resp['api_users'],
            resp['access_key_over'],
            resp['access_key_used']
        ]


def get_iam_user_tile(auth):
    response = api.utils.get_tile_model()
    aws = AWS(auth)
    iam_metrics = get_iam_users(aws, 'user')
    keys = [{'key': 'users', 'label': 'Login Accounts'}]
    tags = ['Total', 'Creds Over 180', 'Access Over 180', 'Missing MFA']
    response.update({'keys': keys, 'key_type': 'string'})
    for i in range(len(iam_metrics)):
        response['data'].append(api.utils.set_chart_tile_data(
            keys, tags[i], tags[i], iam_metrics[i]))
    return response


def get_iam_api_tile(auth):
    response = api.utils.get_tile_model()
    aws = AWS(auth)
    iam_metrics = get_iam_users(aws, 'api')
    keys = [{'key': 'users', 'label': 'API Accounts'}]
    tags = ['Total', 'Creds Over 180', 'Access Over 180']
    response.update({'keys': keys, 'key_type': 'string'})
    for i in range(len(iam_metrics)):
        response['data'].append(api.utils.set_chart_tile_data(
            keys, tags[i], tags[i], iam_metrics[i]))
    return response


def get_summary(auth):
    response = api.utils.get_tile_model()
    aws = AWS(auth)
    response['data'].append(get_ec2_summary(aws))
    response['data'].append(get_s3_summary(aws))
    response['data'].append(get_http_summary(aws))
    response['data'].append(get_rest_summary(aws))
    response['data'].append(get_vpc_summary(aws))
    response['data'].append(get_subnet_summary(aws))
    response['data'].append(get_sg_summary(aws))
    return response


def get_ec2_details(auth):
    data = [
        "|   |   |   |   |",
        "| - | - | - | - |",
    ]
    response = api.utils.get_tile_model()
    ec2 = AWS(auth)
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
    ['Infrastructure Summary',
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
     'last_hour'],
    ['Overall Flows',
     'donut_graph',
     ['AWS'],
     'Summary of flow allows and blocks',
     'Summary of flow allows and blocks',
     'aws_vpc_flows',
     ['last_24_hours', 'last_7_days'],
     'last_24_hours'],
    ['IAM Login Users',
     'vertical_bar_chart',
     ['AWS'],
     'Summary of AWS IAM Login Users',
     'Summary of AWS IAM Login Users',
     'aws_iam_login',
     ['last_hour'],
     'last_hour'],
    ['IAM API Users',
     'horizontal_bar_chart',
     ['AWS'],
     'Summary of AWS IAM API Users',
     'Summary of AWS IAM API Users',
     'aws_iam_api',
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
    elif req_id == 'aws_vpc_flows':
        data = get_flow_tile(auth, 1)
        return jsonify_data(data)
    elif req_id == 'aws_iam_login':
        return jsonify_data(get_iam_user_tile(auth))
    elif req_id == 'aws_iam_api':
        return jsonify_data(get_iam_api_tile(auth))
    else:
        return jsonify_data({})
