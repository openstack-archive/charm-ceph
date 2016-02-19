#!/usr/bin/python
import sys

sys.path.append('hooks')

import rados
from ceph_ops import connect
from charmhelpers.core.hookenv import action_get, log, action_fail


def remove_pool():
    try:
        pool_name = action_get("name")
        cluster = connect()
        log("Deleting pool: {}".format(pool_name))
        cluster.delete_pool(str(pool_name))  # Convert from unicode
        cluster.shutdown()
    except (rados.IOError,
            rados.ObjectNotFound,
            rados.NoData,
            rados.NoSpace,
            rados.PermissionError) as e:
        log(e)
        action_fail(e)


if __name__ == '__main__':
    remove_pool()
