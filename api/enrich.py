from functools import partial
from flask import Blueprint, current_app
from datetime import datetime
from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data
import api.vpc_logs as vpc_logs

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


def sort_events(event):
    return datetime.timestamp(datetime.strptime(event['observed_time']['end_time'], "%Y-%m-%dT%H:%M:%S.%fZ"))


def set_target(ip, type, start, end):
    return {
            "type": type,
            "observables": [
                {
                    "value": ip,
                    "type": "ip"
                }
            ],
            "observed_time": {
                "start_time": start.replace(' ', 'T') + '.000Z',
                "end_time": end.replace(' ', 'T') + '.000Z'
            }
        }


def set_relation(src, dst, relation):
    return {
        "origin": "AWS VPC Flow Relay",
        "relation": relation,
        "source": {
            "value": src,
            "type": "ip"
        },
        "related": {
            "value": dst,
            "type": "ip"
        }
    }


def set_observable(ip):
    return {
                "value": ip,
                "type": "ip"
            }


def get_doc():
    return {
        "description": "VPC Flow Record Sighting",
        "schema_version": "1.1.3",
        "relations": [
        ],
        "observables": [
        ],
        "type": "sighting",
        "source": "AWS VPC Flow",
        "targets": [
        ],
        "resolution": "allowed",
        "internal": True,
        "count": 1,
        "id": '',
        "severity": "Unknown",
        "tlp": "white",
        "confidence": "High",
        "observed_time": {
            "start_time": "2021-04-19T03:01:27.000Z",
            "end_time": "2021-04-19T03:01:27.000Z"
        },
        "sensor": "network.sensor"
    }


def set_flow_doc(flow):
    doc = get_doc()
    doc['count'] = flow['count']
    doc['severity'] = flow['severity']
    doc['resolution'] = flow['resolution']
    doc['id'] = "transient:" + flow['srcaddr'] + '_' + flow['dstaddr']
    doc['observed_time']['start_time'] = flow['starttime'].replace(' ', 'T') + '.000Z'
    doc['observed_time']['end_time'] = flow['timestamp'].replace(' ', 'T') + '.000Z'
    return doc


def set_nat_doc(src, dst):
    doc = get_doc()
    doc['count'] = 1
    doc['id'] = "transient:" + src + '_' + dst
    doc['observed_time']['start_time'] = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    doc['observed_time']['end_time'] = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    return doc


def get_model():
    return {
            "sightings": {
                "count": 1,
                "docs": [
                ]
            }
        }


def group_observables(relay_input):
    # Leave only unique observables ( deduplicate observable )  and select some specific observable type
    result = []
    for observable in relay_input:
        o_value = observable['value']
        o_type = observable['type'].lower()

        # Get only supported types by this third party
        if o_type in current_app.config['CCT_OBSERVABLE_TYPES']:
            obj = {'type': o_type, 'value': o_value}
            if obj in result:
                continue
            result.append(obj)
    return result


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    response = get_model()
    auth = get_jwt()
    vpc = vpc_logs.VPC(auth)
    ob = group_observables(get_observables())
    for o in ob:
        nat = None
        if not vpc.check_local(o['value']):
            try:
                nat = vpc.ip_mapping[o['value']]
            except:
                pass
        natted = None
        if vpc.check_local(o['value']):
            try:
                natted = vpc.ip_mapping[o['value']]
            except:
                pass
        if nat:
            flows = vpc.parse_events(nat)
        else:
            flows = vpc.parse_events(o['value'])
        all_flows = flows[0] + flows[1]
        response['sightings']['count'] = len(ob)
        for f in all_flows:
            try:
                doc = set_flow_doc(f)
                doc['relations'].append(set_relation(f['srcaddr'], f['dstaddr'], 'Connected_To'))
                doc['observables'].append(set_observable(o['value']))
                doc['internal'] = vpc.check_local(f['dstaddr'])
                if doc['internal']:
                    doc['targets'].append(set_target(f['dstaddr'], 'endpoint', f['starttime'], f['timestamp']))
                if vpc.check_local(o['value']):
                    try:
                        doc['relations'].append(set_relation(o['value'], natted, 'NAT_Translates_To'))
                        doc['targets'].append(set_target(natted,
                                                         'network.gateway',
                                                         f['starttime'],
                                                         f['timestamp']))
                    except:
                        pass
                else:
                    try:

                        doc['relations'].append(set_relation(o['value'], nat, 'NAT_Translated_To'))
                        doc['targets'].append(set_target(nat,
                                                         'endpoint',
                                                         f['starttime'],
                                                         f['timestamp']))
                    except:
                        pass
                response['sightings']['docs'].append(doc)
            except:
                continue
    if auth['LIMIT'].lower() == 'all':
        return jsonify_data(response)
    else:
        updated_docs = sorted(response['sightings']['docs'], key=sort_events, reverse=True)
        response['sightings']['docs'] = updated_docs[:int(auth['LIMIT'])]
        return jsonify_data(response)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
