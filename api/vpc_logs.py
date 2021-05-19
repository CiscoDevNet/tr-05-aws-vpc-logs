import boto3
from botocore.config import Config
from datetime import datetime, timedelta
import dateutil.tz
import ipaddress


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
        response = False
        for sn in self.subnets['Subnets']:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(sn['CidrBlock']):
                response = True
        return response

    def get_flows(self, delta=None):
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

    def parse_events(self, ip):
        src_targets = []
        src_counts = {}
        dst_targets = []
        dst_counts = {}
        for event in self.events:
            split = event['message'].split(' ')
            if split[3] == '-' or split[4] == '-':
                continue
            if split[3] == ip or split[4] == ip:
                if split[12] == 'REJECT':
                    if not self.SHOW_BLOCKS:
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
                    if len(src_targets) > self.FLOWS:
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
                    if len(dst_targets) > self.FLOWS:
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
        self.SHOW_BLOCKS = login['SHOW_BLOCKS']
        self.FLOWS = 50
        if 'FLOWS' in login.keys():
            self.FLOWS = login['FLOWS']
        self.now_timestamp = None
        self.end_timestamp = None
        self.get_subnets()

