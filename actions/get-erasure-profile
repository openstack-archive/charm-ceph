#!/usr/bin/python
__author__ = 'chris'
import sys

sys.path.append('hooks')

from charmhelpers.contrib.storage.linux.ceph import get_erasure_profile
from charmhelpers.core.hookenv import action_get, action_set


def make_erasure_profile():
    name = action_get("name")
    out = get_erasure_profile(service='admin', name=name)
    action_set({'message': out})


if __name__ == '__main__':
    make_erasure_profile()
