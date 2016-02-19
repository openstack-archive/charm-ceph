#!/usr/bin/python
__author__ = 'chris'
import sys
from subprocess import check_output, CalledProcessError

sys.path.append('hooks')

from charmhelpers.core.hookenv import action_get, log, action_set, action_fail

if __name__ == '__main__':
    name = action_get("name")
    try:
        out = check_output(['ceph',
                            '--id', 'admin',
                            'osd',
                            'erasure-code-profile',
                            'ls']).decode('UTF-8')
        action_set({'message': out})
    except CalledProcessError as e:
        log(e)
        action_fail("Listing erasure profiles failed with error: {}".format(
            e.message))
