#!/usr/bin/python
import sys

sys.path.append('hooks')
from subprocess import CalledProcessError
from charmhelpers.core.hookenv import action_get, log, action_fail
from charmhelpers.contrib.storage.linux.ceph import remove_pool_snapshot

if __name__ == '__main__':
    name = action_get("pool-name")
    snapname = action_get("snapshot-name")
    try:
        remove_pool_snapshot(service='admin',
                             pool_name=name,
                             snapshot_name=snapname)
    except CalledProcessError as e:
        log(e)
        action_fail("Remove pool snapshot failed with message: {}".format(
            e.message))
