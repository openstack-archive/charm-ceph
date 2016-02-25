#!/usr/bin/python
__author__ = 'chris'
import sys
from subprocess import check_output, CalledProcessError

sys.path.append('hooks')

from charmhelpers.core.hookenv import log, action_set, action_get, action_fail

if __name__ == '__main__':
    name = action_get('pool-name')
    key = action_get('key')
    try:
        out = check_output(['ceph', '--id', 'admin',
                            'osd', 'pool', 'get', name, key]).decode('UTF-8')
        action_set({'message': out})
    except CalledProcessError as e:
        log(e)
        action_fail("Pool get failed with message: {}".format(e.message))
