#!/usr/bin/python
import sys

sys.path.append('hooks')
from subprocess import CalledProcessError
from charmhelpers.core.hookenv import action_get, log, action_fail
from charmhelpers.contrib.storage.linux.ceph import rename_pool

if __name__ == '__main__':
    name = action_get("pool-name")
    new_name = action_get("new-name")
    try:
        rename_pool(service='admin', old_name=name, new_name=new_name)
    except CalledProcessError as e:
        log(e)
        action_fail("Renaming pool failed with message: {}".format(e.message))
