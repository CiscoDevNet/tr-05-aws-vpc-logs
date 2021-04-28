from authlib.jose import jwt
from authlib.jose.errors import DecodeError, BadSignatureError
from flask import request, current_app, jsonify
from datetime import datetime, timedelta
from api.errors import AuthorizationError, InvalidArgumentError


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    try:
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})


tile_types = [
    'donut_graph',
    'metric_group',
    'vertical_bar_chart',
    'horizontal_bar_chart',
    'markdown'
]

icon_types = [
    'device-type',
    'bulleted-list',
    'label-group',
    'static-nat',
    'information',
    'warning',
    'critical-stop',
    'object',
    'vpn',
    'user',
    'view-metadata',
    'umbrella',
    'block'

]

key_types = [
    'timestamp'
]


def get_tile():
    return {
                'description': '',
                'periods': [
                    #'last_24_hours',
                    #'last_7_days',
                    #'last_30_days',
                    #'last_60_days',
                    #'last_90_days'
                ],
                'tags': [],
                'type': '',
                'short_description': '',
                'title': '',
                'default_period': '',
                'id': ''
            }


def set_tile(title, tile_type, tags, s_des, des, id, periods, def_period):
    if tile_type not in tile_type:
        return None
    tile = get_tile()
    tile['title'] = title
    tile['description'] = des
    tile['short_description'] = s_des
    tile['type'] = tile_type
    tile['tags'] = tags
    tile['id'] = id
    tile['periods'] = periods
    tile['default_period'] = def_period
    return tile


def set_time(offset):
    return {
        'start_time': str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
        'end_time': str((datetime.now() + timedelta(hours=offset)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

    }


def set_metric_tile_data(label, icon, link, value):
    if icon not in icon_types:
        icon = 'device-type'
    return {
        'value': value,
        'value-unit': 'integer',
        'icon': icon,
        'link_uri': link,
        'label': label
    }


def set_donut_tile_data(rings, tags, data):
    response = []
    for r in range(len(rings)):
        item = {
                'key': r,
                'value': sum(data[r]),
                'segments': []
            }
        for t in range(len(tags)):
            item['segments'].append({
                'key': t,
                'value': data[r][t]
            })
        response.append(item)
    return response


def set_chart_tile_data(keys, key, label, value):
    return {
        'key': key,
        'label': label,
        'value': value,
        'values': [
            {
                'key': keys[0]['key'],
                'value': value,
                'tooltip': keys[0]['label'] + ' ' + str(value)
            }
        ]
    }


def get_tile_model():
    return {
        'valid_time': set_time(1),
        'observed_time': set_time(1),
        'cache_scope': 'org',
        'data': []
    }


def metric_tile(data):
    mod = get_tile_model()
    for d in data:
        mod['data'].append(set_metric_tile_data(d[0], d[1], d[2], d[3]))
    return mod


def donut_tile(rings, tags, data):
    mod = get_tile_model()
    mod.update({'labels': [
        rings,
        tags
    ]})
    mod['data'] = set_donut_tile_data(rings, tags, data)
    return mod


def chart_tile(key_type, keys, data):
    mod = get_tile_model()
    mod.update({
        'key_type': key_type,
        'keys': keys
    })
    for d in data:
        mod['data'].append(set_chart_tile_data(keys, d[0], d[1], d[2]))
    return mod


def markdown_tile(data):
    mod = get_tile_model()
    mod['data'] = data
    return mod
