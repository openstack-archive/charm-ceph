#!/usr/bin/python
from subprocess import CalledProcessError
import sys

sys.path.append('hooks')

from charmhelpers.core.hookenv import action_get, log, action_fail
from ceph_broker import handle_set_pool_value

if __name__ == '__main__':
    name = action_get("pool-name")
    key = action_get("key")
    value = action_get("value")
    request = {'name': name,
               'key': key,
               'value': value}

    try:
        handle_set_pool_value(service='admin', request=request)
    except CalledProcessError as e:
        log(e.message)
        action_fail("Setting pool key: {} and value: {} failed with "
                    "message: {}".format(key, value, e.message))
