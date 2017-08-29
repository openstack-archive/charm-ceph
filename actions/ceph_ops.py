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
import psutil
import sys
import os
import glob

sys.path.append('hooks')

import rados
from charmhelpers.core.hookenv import log, action_get, action_fail
from charmhelpers.contrib.storage.linux.ceph import pool_set, \
    set_pool_quota, snapshot_pool, remove_pool_snapshot


# Connect to Ceph via Librados and return a connection
def connect():
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
    # Shell out
    pass


def list_pools():
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
    target_device = action_get("device")
    disks = psutil.disk_partitions()
    for dev, mountpoint in disks.iteritems():
        if dev == target_device:
            whoami_file = '{}/whoami'.format(mountpoint)
            with open(whoami_file, 'rb') as whoami:
                try:
                    value = whoami.read()
                    return value.rstrip()
                except IOError:
                    action_fail('Could not read file {}'.format(whoami_file))


def disk_for_osd():
    osd = action_get("osd")
    whoami_path = '/var/lib/ceph/osd/ceph-{}'.format(osd)
    try:
        device = os.stat(whoami_path).st_dev
    except:
        action_fail(
            'Could resolve OSD {}, checked {}'.format(
                osd, whoami_path
            ))
    else:
        return device


def get_health():
    try:
        value = check_output(['ceph', '-s'])
        return value
    except CalledProcessError as e:
        action_fail(e.message)


def list_host_osds():
    osd_ids = []
    osds = glob.glob('/var/lib/ceph/osd/ceph-[0-9]+')
    for osd in osds:
        osd_id = osd.split('-', 2)
        try:
            int(osd_id)
            osd_ids.extend(osd_id)
        except:
            action_fail('Failed to parse OSD ID {}'.format(osd_id))


def list_osds():
    key = action_get("key")
    pool_name = action_get("pool_name")
    try:
        value = check_output(['ceph', 'osd', 'pool', 'get', pool_name, key])
        return value
    except CalledProcessError as e:
        action_fail(e.message)


def pool_get():
    key = action_get("key")
    pool_name = action_get("pool_name")
    try:
        value = check_output(['ceph', 'osd', 'pool', 'get', pool_name, key])
        return value
    except CalledProcessError as e:
        action_fail(e.message)


def set_pool():
    key = action_get("key")
    value = action_get("value")
    pool_name = action_get("pool_name")
    pool_set(service='ceph', pool_name=pool_name, key=key, value=value)


def pool_stats():
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
    pool_name = action_get("pool-name")
    snapshot_name = action_get("snapshot-name")
    remove_pool_snapshot(service='ceph',
                         pool_name=pool_name,
                         snapshot_name=snapshot_name)


# Note only one or the other can be set
def set_pool_max_bytes():
    pool_name = action_get("pool-name")
    max_bytes = action_get("max")
    set_pool_quota(service='ceph',
                   pool_name=pool_name,
                   max_bytes=max_bytes)


def snapshot_ceph_pool():
    pool_name = action_get("pool-name")
    snapshot_name = action_get("snapshot-name")
    snapshot_pool(service='ceph',
                  pool_name=pool_name,
                  snapshot_name=snapshot_name)
