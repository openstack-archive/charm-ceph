# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from subprocess import CalledProcessError, check_output
import rados
import psutil
import sys
import os
import glob

sys.path.append('hooks')

from charmhelpers.core.hookenv import log, action_get, action_fail
from charmhelpers.contrib.storage.linux.ceph import pool_set, \
    set_pool_quota, snapshot_pool, remove_pool_snapshot


def connect():
    """Creates a connection to Ceph using librados."""
    try:
        cluster = rados.Rados(conffile='/etc/ceph/ceph.conf')
        cluster.connect()
        return cluster
    except (rados.IOError,
            rados.ObjectNotFound,
            rados.NoData,
            rados.NoSpace,
            rados.PermissionError) as rados_error:
        log("librados failed with error: {}".format(str(rados_error)))


def create_crush_rule():
    """Stub function."""
    # Shell out
    pass


def list_pools():
    """Return a list of all Ceph pools."""
    try:
        cluster = connect()
        pool_list = cluster.list_pools()
        cluster.shutdown()
        return pool_list
    except (rados.IOError,
            rados.ObjectNotFound,
            rados.NoData,
            rados.NoSpace,
            rados.PermissionError) as e:
        action_fail(e.message)


def osd_for_disk():
    """
    Returns the OSD ID for a given block device.

    Block device is specified by the 'device' action parameter.
    If the device can not be found, or the 'whoami' file on
    the OSD's backing device's file system cannot be found,
    the action will fail, and 'unknown' will be returned.
    """
    target_device = action_get("device")
    disks = psutil.disk_partitions()
    for dev, mountpoint in disks.iteritems():
        if dev == target_device:
            break  # found the device mountpoint
    if mountpoint:
        whoami_file = '{}/whoami'.format(mountpoint)
        with open(whoami_file, 'r') as whoami:
            try:
                value = whoami.read().rstrip()
                return value
            except IOError:
                action_fail('Could not read file {}'.format(whoami_file))
                return "unknown"
    else:
        action_fail('Could not find device {}'.format(target_device))
        return "unknown"


def disk_for_osd():
    """
    Returns the block device backing an OSD.

    The OSD ID is specified by the 'osd' action parameter.
    If the block device cannot be determined by using the 'stat'
    call on the OSD's directory under '/var/lib/ceph/osd' to return
    the mounted filesystem's backing device, 'unknown' will be returned,
    and the action will fail.
    """
    osd = action_get("osd")
    whoami_path = '/var/lib/ceph/osd/ceph-{}'.format(osd)
    try:
        device = os.stat(whoami_path).st_dev
    except:
        action_fail(
            'Could resolve OSD {}, checked {}'.format(
                osd, whoami_path
            ))
        return 'unknown'
    else:
        return device


def get_health():
    """
    Returns the output of 'ceph health'.

    On error, 'unknown' is returned.
    """
    try:
        value = check_output(['ceph', 'health'])
        return value
    except CalledProcessError as e:
        action_fail(e.message)
        return 'unknown'


def list_host_osds():
    """
    Returns a list of OSD IDs currently present on this host.

    Scans /var/lib/ceph/osd to determine this information, and is
    useful for comparison with the Ceph monitor's OSD list to
    identify problems with missing or redundant OSD volumes.
    """
    osd_ids = []
    osds = glob.glob('/var/lib/ceph/osd/ceph-[0-9]+')
    for osd in osds:
        osd_id = osd.split('-')[-1]
        try:
            int(osd_id)
            osd_ids.extend(osd_id)
        except:
            action_fail('Failed to parse OSD ID {}'.format(osd_id))
            return 'unknown'
    return osd_ids


def list_osds():
    """Returns a list of OSDs obtained by running 'ceph osd tree'."""
    try:
        value = check_output(['ceph', 'osd', 'tree'])
        return value
    except CalledProcessError as e:
        action_fail(e.message)


def pool_get():
    """
    Returns a key from a pool using 'ceph osd pool get'.

    The key is provided via the 'key' action parameter and the
    pool provided by the 'pool_name' parameter. These are used when
    running 'ceph osd pool get <pool_name> <key>', the result of
    which is returned.

    On failure, 'unknown' will be returned.
    """
    key = action_get("key")
    pool_name = action_get("pool_name")
    try:
        value = check_output(['ceph', 'osd', 'pool', 'get', pool_name, key])
        return value
    except CalledProcessError as e:
        action_fail(e.message)
        return 'unknown'


def set_pool():
    """
    Sets an arbitrary key key in a Ceph pool.

    Sets the key specified by the action parameter 'key' to the value
    specified in the action parameter 'value' for the pool specified
    by the action parameter 'pool_name' using the charmhelpers
    'pool_set' function.
    """
    key = action_get("key")
    value = action_get("value")
    pool_name = action_get("pool_name")
    pool_set(service='ceph', pool_name=pool_name, key=key, value=value)


def pool_stats():
    """
    Returns statistics for a pool.

    The pool name is provided by the action parameter 'pool-name'.
    """
    try:
        pool_name = action_get("pool-name")
        cluster = connect()
        ioctx = cluster.open_ioctx(pool_name)
        stats = ioctx.get_stats()
        ioctx.close()
        cluster.shutdown()
        return stats
    except (rados.Error,
            rados.IOError,
            rados.ObjectNotFound,
            rados.NoData,
            rados.NoSpace,
            rados.PermissionError) as e:
        action_fail(e.message)


def delete_pool_snapshot():
    """
    Delete a pool snapshot.

    Deletes a snapshot from the pool provided by the action
    parameter 'pool-name', with the snapshot name provided by
    action parameter 'snapshot-name'
    """
    pool_name = action_get("pool-name")
    snapshot_name = action_get("snapshot-name")
    remove_pool_snapshot(service='ceph',
                         pool_name=pool_name,
                         snapshot_name=snapshot_name)


# Note only one or the other can be set
def set_pool_max_bytes():
    """
    Sets the max bytes quota for a pool.

    Sets the pool quota maximum bytes for the pool specified by
    the action parameter 'pool-name' to the value specified by
    the action parameter 'max'
    """
    pool_name = action_get("pool-name")
    max_bytes = action_get("max")
    set_pool_quota(service='ceph',
                   pool_name=pool_name,
                   max_bytes=max_bytes)


def snapshot_ceph_pool():
    """
    Snapshots a Ceph pool.

    Snapshots the pool provided in action parameter 'pool-name' and
    uses the parameter provided in the action parameter 'snapshot-name'
    as the name for the snapshot.
    """
    pool_name = action_get("pool-name")
    snapshot_name = action_get("snapshot-name")
    snapshot_pool(service='ceph',
                  pool_name=pool_name,
                  snapshot_name=snapshot_name)
