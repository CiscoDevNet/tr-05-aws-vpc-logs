from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = 'INSERT - GENERATED JWT SECRET HERE'

    CCT_OBSERVABLE_TYPES = {
        'ip': {}
    }

    CTR_HEADERS = {
        'User-Agent': ('SecureX Threat Response Integrations '
                       '<tr-integrations-support@cisco.com>')
    }
