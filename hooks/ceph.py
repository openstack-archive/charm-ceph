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

import json
import subprocess
import time
import os
import re
import sys

from charmhelpers.contrib.storage.linux.utils import (
    is_block_device,
    zap_disk,
    is_device_mounted)
from charmhelpers.core.host import (
    mkdir,
    chownr,
    service_restart,
    lsb_release,
    cmp_pkgrevno)
from charmhelpers.core.hookenv import (
    log,
    ERROR,
    cached,
    status_set,
    WARNING)
from charmhelpers.fetch import (
    apt_cache
)
from utils import (
    get_unit_hostname,
)

LEADER = 'leader'
PEON = 'peon'
QUORUM = [LEADER, PEON]

PACKAGES = ['ceph', 'gdisk', 'ntp', 'btrfs-tools', 'python-ceph', 'xfsprogs']


def ceph_user():
    if get_version() > 1:
        return 'ceph'
    else:
        return "root"


def get_local_mon_ids():
    """
    This will list the /var/lib/ceph/mon/* directories and try
    to split the ID off of the directory name and return it in
    a list

    :return: list.  A list of monitor identifiers :raise: OSError if
     something goes wrong with listing the directory.
    """
    mon_ids = []
    mon_path = os.path.join(os.sep, 'var', 'lib', 'ceph', 'mon')
    if os.path.exists(mon_path):
        try:
            dirs = os.listdir(mon_path)
            for mon_dir in dirs:
                # Basically this takes everything after ceph- as the monitor ID
                match = re.search('ceph-(?P<mon_id>.*)', mon_dir)
                if match:
                    mon_ids.append(match.group('mon_id'))
        except OSError:
            raise
    return mon_ids


def get_version():
    """Derive Ceph release from an installed package."""
    import apt_pkg as apt

    cache = apt_cache()
    package = "ceph"
    try:
        pkg = cache[package]
    except:
        # the package is unknown to the current apt cache.
        e = 'Could not determine version of package with no installation ' \
            'candidate: %s' % package
        error_out(e)

    if not pkg.current_ver:
        # package is known, but no version is currently installed.
        e = 'Could not determine version of uninstalled package: %s' % package
        error_out(e)

    vers = apt.upstream_version(pkg.current_ver.ver_str)

    # x.y match only for 20XX.X
    # and ignore patch level for other packages
    match = re.match('^(\d+)\.(\d+)', vers)

    if match:
        vers = match.group(0)
    return float(vers)


def error_out(msg):
    log("FATAL ERROR: %s" % msg,
        level=ERROR)
    sys.exit(1)


def is_quorum():
    asok = "/var/run/ceph/ceph-mon.{}.asok".format(get_unit_hostname())
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        "ceph",
        "--admin-daemon",
        asok,
        "mon_status"
    ]
    if os.path.exists(asok):
        try:
            result = json.loads(subprocess.check_output(cmd))
        except subprocess.CalledProcessError:
            return False
        except ValueError:
            # Non JSON response from mon_status
            return False
        if result['state'] in QUORUM:
            return True
        else:
            return False
    else:
        return False


def is_leader():
    asok = "/var/run/ceph/ceph-mon.{}.asok".format(get_unit_hostname())
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        "ceph",
        "--admin-daemon",
        asok,
        "mon_status"
    ]
    if os.path.exists(asok):
        try:
            result = json.loads(subprocess.check_output(cmd))
        except subprocess.CalledProcessError:
            return False
        except ValueError:
            # Non JSON response from mon_status
            return False
        if result['state'] == LEADER:
            return True
        else:
            return False
    else:
        return False


def wait_for_quorum():
    while not is_quorum():
        log("Waiting for quorum to be reached")
        time.sleep(3)


def add_bootstrap_hint(peer):
    asok = "/var/run/ceph/ceph-mon.{}.asok".format(get_unit_hostname())
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        "ceph",
        "--admin-daemon",
        asok,
        "add_bootstrap_peer_hint",
        peer
    ]
    if os.path.exists(asok):
        # Ignore any errors for this call
        subprocess.call(cmd)


DISK_FORMATS = [
    'xfs',
    'ext4',
    'btrfs'
]


def is_osd_disk(dev):
    try:
        info = subprocess.check_output(['sgdisk', '-i', '1', dev])
        info = info.split("\n")  # IGNORE:E1103
        for line in info:
            if line.startswith(
                    'Partition GUID code: 4FBD7E29-9D25-41B8-AFD0-062C0CEFF05D'
            ):
                return True
    except subprocess.CalledProcessError:
        pass
    return False


def start_osds(devices):
    # Scan for ceph block devices
    rescan_osd_devices()
    if cmp_pkgrevno('ceph', "0.56.6") >= 0:
        # Use ceph-disk activate for directory based OSD's
        for dev_or_path in devices:
            if os.path.exists(dev_or_path) and os.path.isdir(dev_or_path):
                subprocess.check_call(['ceph-disk', 'activate', dev_or_path])


def rescan_osd_devices():
    cmd = [
        'udevadm', 'trigger',
        '--subsystem-match=block', '--action=add'
    ]

    subprocess.call(cmd)


_bootstrap_keyring = "/var/lib/ceph/bootstrap-osd/ceph.keyring"


def is_bootstrapped():
    return os.path.exists(_bootstrap_keyring)


def wait_for_bootstrap():
    while not is_bootstrapped():
        time.sleep(3)


def import_osd_bootstrap_key(key):
    if not os.path.exists(_bootstrap_keyring):
        cmd = [
            "sudo",
            "-u",
            ceph_user(),
            'ceph-authtool',
            _bootstrap_keyring,
            '--create-keyring',
            '--name=client.bootstrap-osd',
            '--add-key={}'.format(key)
        ]
        subprocess.check_call(cmd)


def generate_monitor_secret():
    cmd = [
        'ceph-authtool',
        '/dev/stdout',
        '--name=mon.',
        '--gen-key'
    ]
    res = subprocess.check_output(cmd)

    return "{}==".format(res.split('=')[1].strip())


# OSD caps taken from ceph-create-keys
_osd_bootstrap_caps = {
    'mon': [
        'allow command osd create ...',
        'allow command osd crush set ...',
        r'allow command auth add * osd allow\ * mon allow\ rwx',
        'allow command mon getmap'
    ]
}

_osd_bootstrap_caps_profile = {
    'mon': [
        'allow profile bootstrap-osd'
    ]
}


def parse_key(raw_key):
    # get-or-create appears to have different output depending
    # on whether its 'get' or 'create'
    # 'create' just returns the key, 'get' is more verbose and
    # needs parsing
    key = None
    if len(raw_key.splitlines()) == 1:
        key = raw_key
    else:
        for element in raw_key.splitlines():
            if 'key' in element:
                key = element.split(' = ')[1].strip()  # IGNORE:E1103
    return key


def get_osd_bootstrap_key():
    try:
        # Attempt to get/create a key using the OSD bootstrap profile first
        key = get_named_key('bootstrap-osd',
                            _osd_bootstrap_caps_profile)
    except:
        # If that fails try with the older style permissions
        key = get_named_key('bootstrap-osd',
                            _osd_bootstrap_caps)
    return key


_radosgw_keyring = "/etc/ceph/keyring.rados.gateway"


def import_radosgw_key(key):
    if not os.path.exists(_radosgw_keyring):
        cmd = [
            "sudo",
            "-u",
            ceph_user(),
            'ceph-authtool',
            _radosgw_keyring,
            '--create-keyring',
            '--name=client.radosgw.gateway',
            '--add-key={}'.format(key)
        ]
        subprocess.check_call(cmd)

# OSD caps taken from ceph-create-keys
_radosgw_caps = {
    'mon': ['allow rw'],
    'osd': ['allow rwx']
}
_upgrade_caps = {
    'mon': ['allow rwx']
}

osd_upgrade_caps = {
    'mon': ['allow command "config-key"',
            'allow command "osd tree"',
            'allow command "config-key list"',
            'allow command "config-key put"',
            'allow command "config-key get"',
            'allow command "config-key exists"',
            'allow command "osd out"',
            'allow command "osd in"',
            'allow command "osd rm"',
            'allow command "auth del"',
            ]
}


def get_radosgw_key():
    return get_named_key('radosgw.gateway', _radosgw_caps)


_default_caps = {
    'mon': ['allow rw'],
    'osd': ['allow rwx']
}

admin_caps = {
    'mds': ['allow'],
    'mon': ['allow *'],
    'osd': ['allow *']
}

osd_upgrade_caps = {
    'mon': ['allow command "config-key"',
            'allow command "osd tree"',
            'allow command "config-key list"',
            'allow command "config-key put"',
            'allow command "config-key get"',
            'allow command "config-key exists"',
            ]
}


def get_upgrade_key():
    return get_named_key('upgrade-osd', _upgrade_caps)


def get_named_key(name, caps=None):
    caps = caps or _default_caps
    cmd = [
        "sudo",
        "-u",
        ceph_user(),
        'ceph',
        '--name', 'mon.',
        '--keyring',
        '/var/lib/ceph/mon/ceph-{}/keyring'.format(
            get_unit_hostname()
        ),
        'auth', 'get-or-create', 'client.{}'.format(name),
    ]
    # Add capabilities
    for subsystem, subcaps in caps.iteritems():
        cmd.extend([
            subsystem,
            '; '.join(subcaps),
        ])
    return parse_key(subprocess.check_output(cmd).strip())  # IGNORE:E1103


def upgrade_key_caps(key, caps):
    """ Upgrade key to have capabilities caps """
    if not is_leader():
        # Not the MON leader OR not clustered
        return
    cmd = [
        "sudo", "-u", ceph_user(), 'ceph', 'auth', 'caps', key
    ]
    for subsystem, subcaps in caps.iteritems():
        cmd.extend([subsystem, '; '.join(subcaps)])
    subprocess.check_call(cmd)


@cached
def systemd():
    return (lsb_release()['DISTRIB_CODENAME'] >= 'vivid')


def bootstrap_monitor_cluster(secret):
    hostname = get_unit_hostname()
    path = '/var/lib/ceph/mon/ceph-{}'.format(hostname)
    done = '{}/done'.format(path)
    if systemd():
        init_marker = '{}/systemd'.format(path)
    else:
        init_marker = '{}/upstart'.format(path)

    keyring = '/var/lib/ceph/tmp/{}.mon.keyring'.format(hostname)

    if os.path.exists(done):
        log('bootstrap_monitor_cluster: mon already initialized.')
    else:
        # Ceph >= 0.61.3 needs this for ceph-mon fs creation
        mkdir('/var/run/ceph', owner=ceph_user(),
              group=ceph_user(), perms=0o755)
        mkdir(path, owner=ceph_user(), group=ceph_user())
        # end changes for Ceph >= 0.61.3
        try:
            subprocess.check_call(['ceph-authtool', keyring,
                                   '--create-keyring', '--name=mon.',
                                   '--add-key={}'.format(secret),
                                   '--cap', 'mon', 'allow *'])

            subprocess.check_call(['ceph-mon', '--mkfs',
                                   '-i', hostname,
                                   '--keyring', keyring])
            chownr(path, ceph_user(), ceph_user())
            with open(done, 'w'):
                pass
            with open(init_marker, 'w'):
                pass

            if systemd():
                subprocess.check_call(['systemctl', 'enable', 'ceph-mon'])
                service_restart('ceph-mon')
            else:
                service_restart('ceph-mon-all')
        except:
            raise
        finally:
            os.unlink(keyring)


def update_monfs():
    hostname = get_unit_hostname()
    monfs = '/var/lib/ceph/mon/ceph-{}'.format(hostname)
    if systemd():
        init_marker = '{}/systemd'.format(monfs)
    else:
        init_marker = '{}/upstart'.format(monfs)
    if os.path.exists(monfs) and not os.path.exists(init_marker):
        # Mark mon as managed by upstart so that
        # it gets start correctly on reboots
        with open(init_marker, 'w'):
            pass


def osdize(dev, osd_format, osd_journal, reformat_osd=False,
           ignore_errors=False):
    if dev.startswith('/dev'):
        osdize_dev(dev, osd_format, osd_journal, reformat_osd, ignore_errors)
    else:
        osdize_dir(dev)


def osdize_dev(dev, osd_format, osd_journal, reformat_osd=False,
               ignore_errors=False):
    if not os.path.exists(dev):
        log('Path {} does not exist - bailing'.format(dev))
        return

    if not is_block_device(dev):
        log('Path {} is not a block device - bailing'.format(dev))
        return

    if is_osd_disk(dev) and not reformat_osd:
        log('Looks like {} is already an OSD, skipping.'.format(dev))
        return

    if is_device_mounted(dev):
        log('Looks like {} is in use, skipping.'.format(dev))
        return

    status_set('maintenance', 'Initializing device {}'.format(dev))
    cmd = ['ceph-disk', 'prepare']
    # Later versions of ceph support more options
    if cmp_pkgrevno('ceph', '0.48.3') >= 0:
        if osd_format:
            cmd.append('--fs-type')
            cmd.append(osd_format)
        if reformat_osd:
            cmd.append('--zap-disk')
        cmd.append(dev)
        if osd_journal and os.path.exists(osd_journal):
            cmd.append(osd_journal)
    else:
        # Just provide the device - no other options
        # for older versions of ceph
        cmd.append(dev)
        if reformat_osd:
            zap_disk(dev)

    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        if ignore_errors:
            log('Unable to initialize device: {}'.format(dev), WARNING)
        else:
            log('Unable to initialize device: {}'.format(dev), ERROR)
            raise e


def osdize_dir(path):
    if os.path.exists(os.path.join(path, 'upstart')):
        log('Path {} is already configured as an OSD - bailing'.format(path))
        return

    if cmp_pkgrevno('ceph', "0.56.6") < 0:
        log('Unable to use directories for OSDs with ceph < 0.56.6',
            level=ERROR)
        raise

    mkdir(path, owner=ceph_user(), group=ceph_user(), perms=0o755)
    chownr('/var/lib/ceph', ceph_user(), ceph_user())
    cmd = [
        'sudo', '-u', ceph_user(),
        'ceph-disk',
        'prepare',
        '--data-dir',
        path
    ]
    subprocess.check_call(cmd)


def filesystem_mounted(fs):
    return subprocess.call(['grep', '-wqs', fs, '/proc/mounts']) == 0


def get_local_osd_ids():
    """
    This will list the /var/lib/ceph/osd/* directories and try
    to split the ID off of the directory name and return it in
    a list

    :return: list.  A list of osd identifiers :raise: OSError if
     something goes wrong with listing the directory.
    """
    osd_ids = []
    osd_path = os.path.join(os.sep, 'var', 'lib', 'ceph', 'osd')
    if os.path.exists(osd_path):
        try:
            dirs = os.listdir(osd_path)
            for osd_dir in dirs:
                osd_id = osd_dir.split('-')[1]
                if _is_int(osd_id):
                    osd_ids.append(osd_id)
        except OSError:
            raise
    return osd_ids


def _is_int(v):
    """Return True if the object v can be turned into an integer."""
    try:
        int(v)
        return True
    except ValueError:
        return False
