#!/usr/bin/python
import sys

sys.path.append('hooks')
from subprocess import check_output, CalledProcessError
from charmhelpers.core.hookenv import log, action_set, action_fail

if __name__ == '__main__':
    try:
        out = check_output(['ceph', '--id', 'admin',
                            'df']).decode('UTF-8')
        action_set({'message': out})
    except CalledProcessError as e:
        log(e)
        action_fail("ceph df failed with message: {}".format(e.message))
