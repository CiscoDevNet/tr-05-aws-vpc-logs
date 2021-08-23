import os
import os.path
from os import path
import argparse
import subprocess
import http.client
import base64
import json
import string
import secrets
import ssl


parser = argparse.ArgumentParser(description='SecureX Relay Deployment Tool.', prog='SecureX Relay Deployer')
parser.add_argument('o', help='Operation to be performed, can be "deploy, update, or remove"')
parser.add_argument('-r', help='AWS region serverless app will be deployed. Example: "-r us-east-1"')
parser.add_argument('-p', help='Project name for serverless function and required buckets. Example: "-p Demo SecureX Relay"')
parser.add_argument('-x', help='SecureX Region US, EU, APJC. Example: "-i US"')
parser.add_argument('-i', help='SecureX API Client ID. Example: "-i client_......"')
parser.add_argument('-s', help='SecureX API Client Secret')
parser.add_argument('-m', help='Memory for Serverless Instance. Example "-m 4096"', type=int, required=False)
parser.add_argument('-t', help='Relay Timeout in Seconds. Example "-t 90"', type=int, required=False)


def create_zappa_config(region, project, secret, memory, timeout):
    if not memory:
        memory = 4096
    if not timeout:
        timeout = 90
    cfg = {
        "prod": {
            "app_function": "app.app",
            "aws_region": region,
            "keep_warm": False,
            "log_level": "INFO",
            "profile_name": "serverless",
            "project_name": project,
            "runtime": "python3.7",
            "s3_bucket": "zappa-" + project + "prod-s3",
            "memory_size": memory,
            "timeout_seconds": timeout,
            "environment_variables": {
                "SECRET_KEY": secret
            }
        }
    }
    with open('zappa_settings.json', 'w') as zappa_file:
        zappa_file.write(json.dumps(cfg))
    print('Zappa configuration file created  \n')
    return True


def get_module(url, sec):
    with open('module_type.json', 'r') as module_file:
        module = json.loads(module_file.read())
        module['properties']['url'] = url
        module['properties']['configuration-token-key'] = sec
        return module


def get_region(r):
    if r.lower() == 'us':
        return '86aad484-6344-42df-922d-916b9947ec47'
    elif r.lower() == 'eu':
        return 'a80c5f4a-74cc-4f4a-8934-571bee72acb5'
    elif r.lower() == 'apjc':
        return 'bab9277c-221f-49f9-a56e-b62641ae348a'


def get_token(i, s):
    b64 = base64.b64encode((i + ':' + s).encode()).decode()
    conn = http.client.HTTPSConnection("visibility.amp.cisco.com", context=ssl._create_unverified_context())
    payload = 'grant_type=client_credentials'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': 'Basic ' + b64
    }
    conn.request("POST", "/iroh/oauth2/token", payload, headers)
    res = conn.getresponse()
    data = res.read()
    if res.status == 200:
        print('Obtained SecureX Auth Token')
        return json.loads(data.decode("utf-8"))['access_token']
    print('Issue Generating Token, Please Check Configuration and Try Again  \n')
    os.close()


def post_module(module, token):
    conn = http.client.HTTPSConnection("visibility.amp.cisco.com", context=ssl._create_unverified_context())
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    conn.request("POST", "/iroh/iroh-int/module-type", json.dumps(module), headers)
    res = conn.getresponse()
    data = res.read()
    if res.status == 201:
        print('SecureX Integration Module Created  \n')
        return json.loads(data.decode("utf-8"))
    print('Issue Deploying Module, Please Check Configuration and Try Again  \n')
    os.close()


def delete_module(module, token):
    conn = http.client.HTTPSConnection("visibility.amp.cisco.com", context=ssl._create_unverified_context())
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    conn.request("DELETE", "/iroh/iroh-int/module-type" + module, '', headers)
    res = conn.getresponse()
    data = res.read()
    if res.status == 204 or res.status == 404:
        print('SecureX Integration Module Deleted  \n')
        delete_integration_id()


def delete_integration_id():
    try:
        os.remove('securex_app_id')
    except:
        return


def get_integration_id():
    try:
        with open('securex_app_id', 'r') as app_id:
            return app_id.read()
    except:
        return


def update_integration_id(i):
    with open('securex_app_id', 'w') as app_id:
        app_id.write(i)


def generate_secret_key():
    """Generate a random 256-bit (i.e. 64-character) secret key."""
    alphabet = string.ascii_letters + string.digits
    print('Encryption Secret Generated')
    return ''.join(secrets.choice(alphabet) for _ in range(64))


def check_operation(o):
    if o.lower() == 'deploy' or o.lower() == 'update' or o.lower() == 'remove':
        return o.lower()


def deploy_zappa(op):
    if op == 'deploy':
        try:
            result = subprocess.run(['zappa', 'deploy', 'prod'], stdout=subprocess.PIPE)
            results = result.stdout.decode('utf-8').split('\n')
            for r in results:
                if 'complete!:' in r.lower():
                    print('App Deploy Complete')
                    return r.split('complete!:')[1].strip()
        except:
            op = 'update'
    if op == 'update':
        result = subprocess.run(['zappa', 'update', 'prod'], stdout=subprocess.PIPE)
        print('Updated Serverless App to AWS')
        results = result.stdout.decode('utf-8').split('\n')
        for r in results:
            if 'live!:' in r.lower():
                print('App Update Complete')
                return r.split('live!:')[1].strip()
    if op == 'remove':
        result = subprocess.run(['zappa', 'undeploy', 'prod', '-y'], stdout=subprocess.PIPE)
        print('Deleted Serverless App to AWS')
        return result.stdout.decode('utf-8').split('\n')
    print('Issue Deploying App Please Verify Configuration and Try Again')
    os.close()


def main():
    args = vars(parser.parse_args())
    op = check_operation(args['o'])
    encrypt_sec = generate_secret_key()
    securex_region = get_region(args['x'])
    token = get_token(args['i'], args['s'])
    if not securex_region:
        print('Unknown value for region, must be US, EU, or APJC')
        return
    if op == 'deploy' or op == 'update':
        if create_zappa_config(args['r'], args['p'], encrypt_sec, args['m'], args['t']):
            url = deploy_zappa(op)
            if url:
                if path.exists('securex_app_id'):
                    if op == 'update':
                        print('SecureX module already exists, skipping this step to avoid duplicates')
                        return
                    mod = get_integration_id()
                    delete_module(mod, token)
                module_config = get_module(url, encrypt_sec)
                if module_config:
                    data = post_module(module_config, token)
                    update_integration_id(data['id'])
    if op == 'remove':
        try:
            response = deploy_zappa(op)
        except:
            pass
        mod = get_integration_id()
        if mod:
            delete_module(mod, token)


if __name__ == '__main__':
    main()
