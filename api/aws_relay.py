import boto3
from botocore.config import Config
from datetime import datetime, timedelta
import dateutil.tz
import ipaddress


class AWS:
    ip = None
    config = None
    client = None
    resource = None

    def get_client(self, client):
        return boto3.client(client,
                            aws_access_key_id=self.ACCESS_KEY,
                            aws_secret_access_key=self.SECRET_KEY,
                            config=self.config)

    def get_s3_client(self):
        return boto3.client('s3',
                            aws_access_key_id=self.ACCESS_KEY,
                            aws_secret_access_key=self.SECRET_KEY)

    def get_resource(self, resource):
        sess = boto3.session.Session(aws_access_key_id=self.ACCESS_KEY,
                                     aws_secret_access_key=self.SECRET_KEY,
                                     region_name=self.REGION)
        self.resource = sess.resource(resource)

    def get_instances(self):
        return self.client.describe_instances()

    def get_subnets(self):
        return self.client.describe_subnets()

    def get_vpcs(self):
        vpc = []
        subnets = self.get_subnets()
        for s in subnets['Subnets']:
            if s['VpcId'] not in vpc:
                vpc.append(s['VpcId'])
        return vpc

    def get_security_groups(self):
        return self.client.describe_security_groups()

    def get_instance(self, ip):
        instances = self.get_instances()
        for res in instances['Reservations']:
            for i in res['Instances']:
                if i['PrivateIpAddress'] == ip:
                    return i

    def get_security_group(self, vpc):
        groups = self.get_security_groups()
        for g in groups['SecurityGroups']:
            if g['GroupName'] == 'SecureX-EC2_Isolation-' + vpc:
                return g

    def check_response(self, ip):
        instance = self.get_instance(ip)
        if instance is None:
            return None
        for s in instance['SecurityGroups']:
            if s['GroupName'] == 'SecureX-EC2_Isolation-' + instance['VpcId']:
                return False
        return True

    def create_isolation_sg(self, vpc):
        sg = self.client.create_security_group(
            Description='SecureX auto-generated Security Group for Dynamic Isolation',
            GroupName='SecureX-EC2_Isolation-' + vpc,
            VpcId=vpc,
            TagSpecifications=[
                {
                    'ResourceType': 'security-group',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': 'SecureX-EC2_Isolation-' + vpc
                        },
                    ]
                },
            ],
            DryRun=False
        )

        security_group = self.resource.SecurityGroup(sg['GroupId'])
        security_group.revoke_egress(
            IpPermissions=security_group.ip_permissions_egress)

    def isolate_instance(self, ip):
        instance = self.get_instance(ip)
        isolation_sg = self.get_security_group(instance['VpcId'])
        if isolation_sg is None:
            sg = self.create_isolation_sg(instance['VpcId'])
        old_group_tag = ''
        for old_sgs in instance['SecurityGroups']:
            old_group_tag += old_sgs['GroupId'] + '::'
        ec2 = self.resource
        inst = ec2.Instance(instance['InstanceId'])
        inst.create_tags(
            Tags=[
                {
                    'Key': 'Pre-Isolation-SG',
                    'Value': old_group_tag
                }
            ])
        inst.modify_attribute(Groups=[isolation_sg['GroupId']])

    def un_isolate_instance(self, ip):
        instance = self.get_instance(ip)
        sg = None
        for t in instance['Tags']:
            if t['Key'] == 'Pre-Isolation-SG':
                sg = t['Value'].split('::')
        if sg[-1] == '':
            sg = sg[:-1]
        if sg is not None:
            ec2 = self.resource
            inst = ec2.Instance(instance['InstanceId'])
            inst.modify_attribute(Groups=sg)
            tag = None
            for t in instance['Tags']:
                if t['Key'] == 'Pre-Isolation-SG':
                    tag = t
            if tag is not None:
                inst.delete_tags(Tags=[tag])

    def __init__(self, login):
        self.ACCESS_KEY = login['ACCESS_KEY']
        self.SECRET_KEY = login['SECRET_KEY']
        self.REGION = login['REGION']
        self.config = Config(
            region_name=self.REGION,
            signature_version='v4',
            retries={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )
        if 'NETWORKS' in login.keys():
            self.internal_nets = login['NETWORKS'].split(',')
        else:
            self.internal_nets = None
        self.client = self.get_client('ec2')
        self.get_resource('ec2')


class VPC:
    subnets = []
    events = []
    ip_mapping = {}

    def get_time_delta(self, delta):
        if delta > 10:
            delta = 10
        now_timestamp = int(datetime.timestamp(datetime.now())) * 1000
        end_timestamp = int(datetime.timestamp(datetime.now() + timedelta(days=-delta))) * 1000
        return now_timestamp, end_timestamp

    def get_subnets(self):

        my_config = Config(
            region_name=self.REGION,
            signature_version='v4',
            retries={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )

        client = boto3.client('ec2',
                              aws_access_key_id=self.ACCESS_KEY,
                              aws_secret_access_key=self.SECRET_KEY,
                              config=my_config)
        self.subnets = client.describe_subnets()
        instances = client.describe_instances()
        for res in instances['Reservations']:
            for i in res['Instances']:
                if i['PublicDnsName'] != '':
                    self.ip_mapping.update({i['PrivateIpAddress']: i['PublicIpAddress']})
                    self.ip_mapping.update({i['PublicIpAddress']: i['PrivateIpAddress']})

    def check_local(self, ip):
        if self.internal_nets:
            for n in self.internal_nets:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(n):
                    return True
            return False
        response = False
        for sn in self.subnets['Subnets']:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(sn['CidrBlock']):
                response = True
        return response

    def get_flows(self, delta=None):
        self.events = []
        if delta is None:
            self.now_timestamp, self.end_timestamp = self.get_time_delta(self.LOOKBACK)
        else:
            self.now_timestamp, self.end_timestamp = self.get_time_delta(delta)
        my_config = Config(
            region_name=self.REGION,
            signature_version='v4',
            retries={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )

        client = boto3.client('logs',
                              aws_access_key_id=self.ACCESS_KEY,
                              aws_secret_access_key=self.SECRET_KEY,
                              config=my_config)

        ## For the latest
        stream_response = client.describe_log_streams(
            logGroupName=self.LOG_GROUP,  # Can be dynamic
            orderBy='LastEventTime',  # For the latest events
            limit=50  # the last latest event, if you just want one
        )

        latestlogStream = stream_response["logStreams"]

        for l in latestlogStream:
            if l['lastEventTimestamp'] < self.end_timestamp:
                continue
            self.events += client.get_log_events(
                logGroupName=self.LOG_GROUP,
                logStreamName=l["logStreamName"],
                startTime=self.end_timestamp,
                endTime=self.now_timestamp,
            )['events']

    def parse_events(self, ip, blocks=False):
        src_targets = []
        src_counts = {}
        dst_targets = []
        dst_counts = {}
        total_events = 0
        for event in self.events:
            if total_events >= self.LIMIT:
                break
            split = event['message'].split(' ')
            if split[3] == '-' or split[4] == '-':
                continue
            if split[3] == ip or split[4] == ip:
                if split[12] == 'REJECT':
                    if not blocks:
                        continue
                    action = 'blocked'
                else:
                    action = 'allowed'
                flow = {
                    'timestamp': str(datetime.fromtimestamp(event['timestamp'] / 1000,
                                                            dateutil.tz.gettz(self.TIME_ZONE))),
                    'version': split[0],
                    'account': split[1],
                    'interface': split[2],
                    'srcaddr': split[3],
                    'dstaddr': split[4],
                    'srcport': split[5],
                    'dstport': split[6],
                    'protocol': split[7],
                    'packets': split[8],
                    'bytes': split[9],
                    'start': split[10],
                    'end': split[11],
                    'action': split[12],
                    'resolution': action,
                    'severity': 'Unknown',
                    'internal': False
                }
                if split[3] == ip:
                    if len(src_targets) > self.INGRESS_FLOWS:
                        continue
                    if split[4] not in src_counts.keys():
                        src_counts.update({split[4]: {'count': 1, 'starttime': flow['timestamp']}})
                    else:
                        src_counts[split[4]]['count'] += 1
                        src_counts[split[4]]['time'] =flow['timestamp']
                    if ip not in src_targets:
                        src_targets.append(split[4])
                    src_counts[split[4]].update(flow)
                elif split[4] == ip:
                    if len(dst_targets) > self.EGRESS_FLOWS:
                        continue
                    if split[3] not in dst_counts.keys():
                        dst_counts.update({split[3]: {'count': 1, 'starttime': flow['timestamp']}})
                    else:
                        dst_counts[split[3]]['count'] += 1
                        dst_counts[split[3]]['time'] = flow['timestamp']
                    if ip not in dst_targets:
                        dst_targets.append(split[3])
                    dst_counts[split[3]].update(flow)

        return list(src_counts.values()), list(dst_counts.values())

    def __init__(self, login, lookup_flows=True):
        self.ACCESS_KEY = login['ACCESS_KEY']
        self.SECRET_KEY = login['SECRET_KEY']
        self.REGION = login['REGION']
        self.LOG_GROUP = login['LOG_GROUP']
        self.TIME_ZONE = login['TIME_ZONE']
        self.LOOKBACK = int(login['LOOKBACK'])
        if 'LIMIT' in login.keys():
            self.LIMIT = login['LIMIT']
        else:
            self.LIMIT = 2000
        self.INGRESS_FLOWS = 1000
        if 'INGRESS-FLOWS' in login.keys():
            self.INGRESS_FLOWS = login['INGRESS-FLOWS']
        self.EGRESS_FLOWS = 1000
        if 'EGRESS-FLOWS' in login.keys():
            self.FLOWS = login['EGRESS-FLOWS']
        if 'NETWORKS' in login.keys():
            self.internal_nets = login['NETWORKS'].split(',')
        else:
            self.internal_nets = None
        self.now_timestamp = None
        self.end_timestamp = None
        self.get_subnets()
