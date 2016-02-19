#!/usr/bin/python
__author__ = 'chris'
import sys
from subprocess import check_output, CalledProcessError

sys.path.append('hooks')

from charmhelpers.core.hookenv import log, action_set, action_fail

if __name__ == '__main__':
    try:
        out = check_output(['ceph', '--id', 'admin',
                            'osd', 'lspools']).decode('UTF-8')
        action_set({'message': out})
    except CalledProcessError as e:
        log(e)
        action_fail("List pools failed with error: {}".format(e.message))
