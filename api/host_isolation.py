import boto3
from botocore.config import Config


class EC2:
    ip = None
    config = None
    client = None
    resource = None

    def get_client(self):

        return boto3.client('ec2',
                            aws_access_key_id=self.ACCESS_KEY,
                            aws_secret_access_key=self.SECRET_KEY,
                            config=self.config)

    def get_resource(self):
        sess = boto3.session.Session(aws_access_key_id=self.ACCESS_KEY,
                                     aws_secret_access_key=self.SECRET_KEY,
                                     region_name=self.REGION)
        self.resource = sess.resource('ec2')

    def get_instance(self, ip):
        instances = self.client.describe_instances()
        for res in instances['Reservations']:
            for i in res['Instances']:
                if i['PrivateIpAddress'] == ip:
                    return i

    def get_security_group(self, vpc):
        groups = self.client.describe_security_groups()
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
        self.client = self.get_client()
        self.get_resource()
