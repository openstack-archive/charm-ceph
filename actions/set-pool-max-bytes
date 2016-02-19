#!/usr/bin/python
import sys

sys.path.append('hooks')
from subprocess import CalledProcessError
from charmhelpers.core.hookenv import action_get, log, action_fail
from charmhelpers.contrib.storage.linux.ceph import set_pool_quota

if __name__ == '__main__':
    max_bytes = action_get("max")
    name = action_get("pool-name")
    try:
        set_pool_quota(service='admin', pool_name=name, max_bytes=max_bytes)
    except CalledProcessError as e:
        log(e)
        action_fail("Set pool quota failed with message: {}".format(e.message))
