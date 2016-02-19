#!/usr/bin/python
import sys

sys.path.append('hooks')
from subprocess import CalledProcessError
from charmhelpers.core.hookenv import action_get, log, action_fail
from charmhelpers.contrib.storage.linux.ceph import ErasurePool, ReplicatedPool


def create_pool():
    pool_name = action_get("name")
    pool_type = action_get("pool-type")
    try:
        if pool_type == "replicated":
            replicas = action_get("replicas")
            replicated_pool = ReplicatedPool(name=pool_name,
                                             service='admin',
                                             replicas=replicas)
            replicated_pool.create()

        elif pool_type == "erasure":
            crush_profile_name = action_get("erasure-profile-name")
            erasure_pool = ErasurePool(name=pool_name,
                                       erasure_code_profile=crush_profile_name,
                                       service='admin')
            erasure_pool.create()
        else:
            log("Unknown pool type of {}. Only erasure or replicated is "
                "allowed".format(pool_type))
            action_fail("Unknown pool type of {}. Only erasure or replicated "
                        "is allowed".format(pool_type))
    except CalledProcessError as e:
        action_fail("Pool creation failed because of a failed process. "
                    "Ret Code: {} Message: {}".format(e.returncode, e.message))


if __name__ == '__main__':
    create_pool()
