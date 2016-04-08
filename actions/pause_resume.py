#!/usr/bin/python
# pause/resume actions file.

import os
import sys
from subprocess import check_call

sys.path.append('hooks')

from charmhelpers.core.hookenv import (
    action_fail,
)

from ceph import get_local_osd_ids
from ceph_hooks import assess_status

from utils import (
    set_unit_paused,
    clear_unit_paused,
)


def pause(args):
    """Pause the ceph-osd units on the local machine only.

    Optionally uses the 'osd-number' from juju action param to only pause a
    specific osd.  If all the osds are not stopped then the paused status is
    not set.

    @raises CalledProcessError if the ceph commands fails.
    @raises OSError if it can't get the local osd ids.
    """
    for local_id in get_local_osd_ids():
        cmd = ['ceph', 'osd', 'out', str(local_id)]
        check_call(cmd)
    set_unit_paused()
    assess_status()


def resume(args):
    """Resume the ceph-osd units on this local machine only

    @raises subprocess.CalledProcessError should the osd units fails to resume.
    @raises OSError if the unit can't get the local osd ids
    """
    for local_id in get_local_osd_ids():
        cmd = ['ceph', 'osd', 'in', str(local_id)]
        check_call(cmd)
    clear_unit_paused()
    assess_status()


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        s = "Action {} undefined".format(action_name)
        action_fail(s)
        return s
    else:
        try:
            action(args)
        except Exception as e:
            action_fail("Action {} failed: {}".format(action_name, str(e)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
