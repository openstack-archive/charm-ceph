#!/usr/bin/python
#
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

import os
import sys
import socket

sys.path.append('lib')
import ceph
from ceph.ceph_broker import (
    process_requests
)

from charmhelpers.core import host
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    log,
    DEBUG,
    ERROR,
    config,
    relation_ids,
    related_units,
    is_relation_made,
    relation_get,
    relation_set,
    remote_unit,
    Hooks, UnregisteredHookError,
    service_name,
    relations_of_type,
    status_set,
    storage_get,
    storage_list,
    local_unit,
    application_version_set,
)
from charmhelpers.core.host import (
    service_restart,
    umount,
    mkdir,
    write_file,
    rsync,
    cmp_pkgrevno,
    add_to_updatedb_prunepath,
)
from charmhelpers.fetch import (
    apt_install,
    apt_update,
    filter_installed_packages,
    add_source,
    get_upstream_version,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.openstack.alternatives import install_alternative
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr,
    format_ipv6_addr,
)
from charmhelpers.core.sysctl import create as create_sysctl
from charmhelpers.core.templating import render
from charmhelpers.contrib.storage.linux.ceph import (
    CephConfContext,
)
from utils import (
    get_networks,
    get_public_addr,
    assert_charm_supports_ipv6,
    is_unit_paused_set,
    get_cluster_addr,
)

from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden

hooks = Hooks()

NAGIOS_PLUGINS = '/usr/local/lib/nagios/plugins'
SCRIPTS_DIR = '/usr/local/bin'
STATUS_FILE = '/var/lib/nagios/cat-ceph-status.txt'
STATUS_CRONFILE = '/etc/cron.d/cat-ceph-health'
STORAGE_MOUNT_PATH = '/var/lib/ceph'

# A dict of valid ceph upgrade paths.  Mapping is old -> new
upgrade_paths = {
    'cloud:trusty-juno': 'cloud:trusty-kilo',
    'cloud:trusty-kilo': 'cloud:trusty-liberty',
    'cloud:trusty-liberty': 'cloud:trusty-mitaka',
}


def pretty_print_upgrade_paths():
    lines = []
    for key, value in upgrade_paths.iteritems():
        lines.append("{} -> {}".format(key, value))
    return lines


def check_for_upgrade():
    if not ceph.is_bootstrapped():
        log("Ceph is not bootstrapped, skipping upgrade checks.")
        return

    release_info = host.lsb_release()
    if not release_info['DISTRIB_CODENAME'] == 'trusty':
        log("Invalid upgrade path from {}.  Only trusty is currently "
            "supported".format(release_info['DISTRIB_CODENAME']))
        return

    c = hookenv.config()
    old_version = c.previous('source')
    log('old_version: {}'.format(old_version))
    # Strip all whitespace
    new_version = hookenv.config('source')
    if new_version:
        # replace all whitespace
        new_version = new_version.replace(' ', '')
    log('new_version: {}'.format(new_version))

    if old_version in upgrade_paths:
        if new_version == upgrade_paths[old_version]:
            log("{} to {} is a valid upgrade path.  Proceeding.".format(
                old_version, new_version))
            ceph.roll_monitor_cluster(new_version=new_version,
                                      upgrade_key='admin')
            # Wait for all monitors to finish.
            status_set("maintenance", "Waiting on mons to finish upgrading")
            ceph.wait_for_all_monitors_to_upgrade(new_version=new_version,
                                                  upgrade_key='admin')
            ceph.roll_osd_cluster(new_version=new_version,
                                  upgrade_key='admin')
        else:
            # Log a helpful error message
            log("Invalid upgrade path from {} to {}.  "
                "Valid paths are: {}".format(old_version,
                                             new_version,
                                             pretty_print_upgrade_paths()))


@hooks.hook('install.real')
@harden()
def install():
    execd_preinstall()
    add_source(config('source'), config('key'))
    apt_update(fatal=True)
    apt_install(packages=ceph.PACKAGES, fatal=True)


def az_info():
    az_info = ""
    juju_az_info = os.environ.get('JUJU_AVAILABILITY_ZONE')
    if juju_az_info:
        az_info = "{} juju_availability_zone={}".format(az_info, juju_az_info)
    config_az = config("availability_zone")
    if config_az:
        az_info = "{} config_availability_zone={}".format(az_info, config_az)
    if az_info != "":
        log("AZ Info: " + az_info)
        return az_info


def use_short_objects():
    '''
    Determine whether OSD's should be configured with
    limited object name lengths.

    @return: boolean indicating whether OSD's should be limited
    '''
    if cmp_pkgrevno('ceph', "10.2.0") >= 0:
        if config('osd-format') in ('ext4'):
            return True
        for device in config('osd-devices'):
            if not device.startswith('/dev'):
                # TODO: determine format of directory based
                #       OSD location
                return True
    return False


def get_ceph_context():
    networks = get_networks('ceph-public-network')
    public_network = ', '.join(networks)

    networks = get_networks('ceph-cluster-network')
    cluster_network = ', '.join(networks)

    cephcontext = {
        'auth_supported': config('auth-supported'),
        'mon_hosts': ' '.join(get_mon_hosts()),
        'fsid': config('fsid'),
        'old_auth': cmp_pkgrevno('ceph', "0.51") < 0,
        'osd_journal_size': config('osd-journal-size'),
        'use_syslog': str(config('use-syslog')).lower(),
        'ceph_public_network': public_network,
        'ceph_cluster_network': cluster_network,
        'loglevel': config('loglevel'),
        'dio': str(config('use-direct-io')).lower(),
        'short_object_len': use_short_objects(),
    }

    if config('prefer-ipv6'):
        dynamic_ipv6_address = get_ipv6_addr()[0]
        if not public_network:
            cephcontext['public_addr'] = dynamic_ipv6_address
        if not cluster_network:
            cephcontext['cluster_addr'] = dynamic_ipv6_address
    else:
        cephcontext['public_addr'] = get_public_addr()
        cephcontext['cluster_addr'] = get_cluster_addr()

    if config('customize-failure-domain'):
        az = az_info()
        if az:
            cephcontext['crush_location'] = "root=default {} host={}" \
                .format(az, socket.gethostname())
        else:
            log(
                "Your Juju environment doesn't"
                "have support for Availability Zones"
            )

    # NOTE(dosaboy): these sections must correspond to what is supported in the
    #                config template.
    sections = ['global', 'mds', 'osd', 'mon']
    cephcontext.update(CephConfContext(permitted_sections=sections)())
    return cephcontext


def emit_cephconf():
    # Install ceph.conf as an alternative to support
    # co-existence with other charms that write this file
    charm_ceph_conf = "/var/lib/charm/{}/ceph.conf".format(service_name())
    mkdir(os.path.dirname(charm_ceph_conf), owner=ceph.ceph_user(),
          group=ceph.ceph_user())
    render('ceph.conf', charm_ceph_conf, get_ceph_context(), perms=0o644)
    install_alternative('ceph.conf', '/etc/ceph/ceph.conf',
                        charm_ceph_conf, 100)


JOURNAL_ZAPPED = '/var/lib/ceph/journal_zapped'


@hooks.hook('config-changed')
@harden()
def config_changed():
    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    # Check if an upgrade was requested
    check_for_upgrade()

    log('Monitor hosts are ' + repr(get_mon_hosts()))

    # Pre-flight checks
    if not config('fsid'):
        log('No fsid supplied, cannot proceed.', level=ERROR)
        sys.exit(1)
    if not config('monitor-secret'):
        log('No monitor-secret supplied, cannot proceed.', level=ERROR)
        sys.exit(1)
    if config('osd-format') not in ceph.DISK_FORMATS:
        log('Invalid OSD disk format configuration specified', level=ERROR)
        sys.exit(1)

    sysctl_dict = config('sysctl')
    if sysctl_dict:
        create_sysctl(sysctl_dict, '/etc/sysctl.d/50-ceph-charm.conf')

    emit_cephconf()

    e_mountpoint = config('ephemeral-unmount')
    if e_mountpoint and ceph.filesystem_mounted(e_mountpoint):
        umount(e_mountpoint)

    osd_journal = get_osd_journal()
    if (osd_journal and not os.path.exists(JOURNAL_ZAPPED) and
            os.path.exists(osd_journal)):
        ceph.zap_disk(osd_journal)
        with open(JOURNAL_ZAPPED, 'w') as zapped:
            zapped.write('DONE')

    # Support use of single node ceph
    if not ceph.is_bootstrapped() and int(config('monitor-count')) == 1:
        status_set('maintenance', 'Bootstrapping single Ceph MON')
        ceph.bootstrap_monitor_cluster(config('monitor-secret'))
        ceph.wait_for_bootstrap()

    storage_changed()

    if relations_of_type('nrpe-external-master'):
        update_nrpe_config()
    add_to_updatedb_prunepath(STORAGE_MOUNT_PATH)


@hooks.hook('osd-devices-storage-attached', 'osd-devices-storage-detaching')
def storage_changed():
    if ceph.is_bootstrapped():
        for dev in get_devices():
            ceph.osdize(dev, config('osd-format'), get_osd_journal(),
                        reformat_osd(), config('ignore-device-errors'))
        ceph.start_osds(get_devices())


def get_osd_journal():
    '''
    Returns the block device path to use for the OSD journal, if any.

    If there is an osd-journal storage instance attached, it will be
    used as the journal. Otherwise, the osd-journal configuration will
    be returned.
    '''
    storage_ids = storage_list('osd-journal')
    if storage_ids:
        # There can be at most one osd-journal storage instance.
        return storage_get('location', storage_ids[0])
    return config('osd-journal')


def get_mon_hosts():
    hosts = []
    addr = get_public_addr()
    hosts.append('{}:6789'.format(format_ipv6_addr(addr) or addr))

    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            addr = relation_get('ceph-public-address', unit, relid)
            if addr is not None:
                hosts.append('{}:6789'.format(
                    format_ipv6_addr(addr) or addr))

    hosts.sort()
    return hosts


def get_peer_units():
    """
    Returns a dictionary of unit names from the mon peer relation with
    a flag indicating whether the unit has presented its address
    """
    units = {}
    units[local_unit()] = True
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            addr = relation_get('ceph-public-address', unit, relid)
            units[unit] = addr is not None
    return units


def reformat_osd():
    if config('osd-reformat'):
        return True
    else:
        return False


def get_devices():
    devices = []

    if config('osd-devices'):
        for path in config('osd-devices').split(' '):
            path = path.strip()
            # Make sure its a device which is specified using an
            # absolute path so that the current working directory
            # or any relative path under this directory is not used
            if os.path.isabs(path):
                devices.append(os.path.realpath(path))

    # List storage instances for the 'osd-devices'
    # store declared for this charm too, and add
    # their block device paths to the list.
    storage_ids = storage_list('osd-devices')
    devices.extend((storage_get('location', s) for s in storage_ids))
    return devices


@hooks.hook('mon-relation-joined')
def mon_relation_joined():
    public_addr = get_public_addr()
    for relid in relation_ids('mon'):
        relation_set(relation_id=relid,
                     relation_settings={'ceph-public-address': public_addr})


@hooks.hook('mon-relation-departed',
            'mon-relation-changed')
def mon_relation():
    emit_cephconf()

    moncount = int(config('monitor-count'))
    if len(get_mon_hosts()) >= moncount:
        status_set('maintenance', 'Bootstrapping MON cluster')
        ceph.bootstrap_monitor_cluster(config('monitor-secret'))
        ceph.wait_for_bootstrap()
        for dev in get_devices():
            ceph.osdize(dev, config('osd-format'), get_osd_journal(),
                        reformat_osd(), config('ignore-device-errors'))
        ceph.start_osds(get_devices())
        ceph.wait_for_quorum()
        notify_osds()
        notify_radosgws()
        notify_client()
    else:
        log('Not enough mons ({}), punting.'
            .format(len(get_mon_hosts())))


def notify_osds():
    for relid in relation_ids('osd'):
        osd_relation(relid)


def notify_radosgws():
    for relid in relation_ids('radosgw'):
        for unit in related_units(relid):
            radosgw_relation(relid=relid, unit=unit)


def notify_client():
    for relid in relation_ids('client'):
        client_relation_joined(relid)


@hooks.hook('osd-relation-changed')
@hooks.hook('osd-relation-joined')
def osd_relation(relid=None):
    if ceph.is_quorum():
        log('mon cluster in quorum - providing fsid & keys')
        public_addr = get_public_addr()
        data = {
            'fsid': config('fsid'),
            'osd_bootstrap_key': ceph.get_osd_bootstrap_key(),
            'auth': config('auth-supported'),
            'ceph-public-address': public_addr,
            'osd_upgrade_key': ceph.get_named_key('osd-upgrade',
                                                  caps=ceph.osd_upgrade_caps),
        }

        unit = remote_unit()
        settings = relation_get(rid=relid, unit=unit)
        """Process broker request(s)."""
        if 'broker_req' in settings:
            if ceph.is_leader():
                rsp = process_requests(settings['broker_req'])
                unit_id = unit.replace('/', '-')
                unit_response_key = 'broker-rsp-' + unit_id
                data[unit_response_key] = rsp
            else:
                log("Not leader - ignoring broker request", level=DEBUG)

        relation_set(relation_id=relid,
                     relation_settings=data)
    else:
        log('mon cluster not in quorum - deferring fsid provision')


@hooks.hook('radosgw-relation-changed')
@hooks.hook('radosgw-relation-joined')
def radosgw_relation(relid=None, unit=None):
    # Install radosgw for admin tools
    apt_install(packages=filter_installed_packages(['radosgw']))
    if not unit:
        unit = remote_unit()

    if ceph.is_quorum():
        log('mon cluster in quorum - providing radosgw with keys')
        public_addr = get_public_addr()
        data = {
            'fsid': config('fsid'),
            'radosgw_key': ceph.get_radosgw_key(),
            'auth': config('auth-supported'),
            'ceph-public-address': public_addr,
        }

        settings = relation_get(rid=relid, unit=unit)
        """Process broker request(s)."""
        if 'broker_req' in settings:
            if ceph.is_leader():
                rsp = process_requests(settings['broker_req'])
                unit_id = unit.replace('/', '-')
                unit_response_key = 'broker-rsp-' + unit_id
                data[unit_response_key] = rsp
            else:
                log("Not leader - ignoring broker request", level=DEBUG)

        relation_set(relation_id=relid, relation_settings=data)
    else:
        log('mon cluster not in quorum - deferring key provision')


@hooks.hook('client-relation-joined')
def client_relation_joined(relid=None):
    if ceph.is_quorum():
        log('mon cluster in quorum - providing client with keys')
        service_name = None
        if relid is None:
            units = [remote_unit()]
            service_name = units[0].split('/')[0]
        else:
            units = related_units(relid)
            if len(units) > 0:
                service_name = units[0].split('/')[0]

        if service_name is not None:
            public_addr = get_public_addr()
            data = {'key': ceph.get_named_key(service_name),
                    'auth': config('auth-supported'),
                    'ceph-public-address': public_addr}
            relation_set(relation_id=relid,
                         relation_settings=data)
    else:
        log('mon cluster not in quorum - deferring key provision')


@hooks.hook('client-relation-changed')
def client_relation_changed():
    """Process broker requests from ceph client relations."""
    if ceph.is_quorum():
        settings = relation_get()
        if 'broker_req' in settings:
            if not ceph.is_leader():
                log("Not leader - ignoring broker request", level=DEBUG)
            else:
                rsp = process_requests(settings['broker_req'])
                unit_id = remote_unit().replace('/', '-')
                unit_response_key = 'broker-rsp-' + unit_id
                # broker_rsp is being left for backward compatibility,
                # unit_response_key superscedes it
                data = {
                    'broker_rsp': rsp,
                    unit_response_key: rsp,
                }
                relation_set(relation_settings=data)
    else:
        log('mon cluster not in quorum', level=DEBUG)


@hooks.hook('upgrade-charm.real')
@harden()
def upgrade_charm():
    emit_cephconf()
    apt_install(packages=filter_installed_packages(ceph.PACKAGES), fatal=True)
    ceph.update_monfs()
    mon_relation_joined()
    if is_relation_made("nrpe-external-master"):
        update_nrpe_config()


@hooks.hook('start')
def start():
    # In case we're being redeployed to the same machines, try
    # to make sure everything is running as soon as possible.
    if ceph.systemd():
        service_restart('ceph-mon')
    else:
        service_restart('ceph-mon-all')
    if ceph.is_bootstrapped():
        ceph.start_osds(get_devices())


@hooks.hook('nrpe-external-master-relation-joined')
@hooks.hook('nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    # lockfile-create is used by collect_ceph_status
    apt_install(['python-dbus', 'lockfile-progs'])
    log('Refreshing nagios checks')
    if os.path.isdir(NAGIOS_PLUGINS):
        rsync(os.path.join(os.getenv('CHARM_DIR'), 'files', 'nagios',
                           'check_ceph_status.py'),
              os.path.join(NAGIOS_PLUGINS, 'check_ceph_status.py'))

    script = os.path.join(SCRIPTS_DIR, 'collect_ceph_status.sh')
    rsync(os.path.join(os.getenv('CHARM_DIR'), 'files',
                       'nagios', 'collect_ceph_status.sh'),
          script)
    cronjob = "{} root {}\n".format('*/5 * * * *', script)
    write_file(STATUS_CRONFILE, cronjob)

    # Find out if nrpe set nagios_hostname
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe_setup.add_check(
        shortname="ceph",
        description='Check Ceph health {%s}' % current_unit,
        check_cmd='check_ceph_status.py -f {}'.format(STATUS_FILE)
    )
    nrpe_setup.write()


VERSION_PACKAGE = 'ceph-common'


def assess_status():
    """Assess status of current unit"""
    application_version_set(get_upstream_version(VERSION_PACKAGE))
    # check to see if the unit is paused.
    if is_unit_paused_set():
        status_set('maintenance',
                   "Paused. Use 'resume' action to resume normal service.")
        return
    moncount = int(config('monitor-count'))
    units = get_peer_units()
    # not enough peers and mon_count > 1
    if len(units.keys()) < moncount:
        status_set('blocked', 'Insufficient peer units to bootstrap'
                              ' cluster (require {})'.format(moncount))
        return

    # mon_count > 1, peers, but no ceph-public-address
    ready = sum(1 for unit_ready in units.itervalues() if unit_ready)
    if ready < moncount:
        status_set('waiting', 'Peer units detected, waiting for addresses')
        return

    # active - bootstrapped + quorum status check
    if ceph.is_bootstrapped() and ceph.is_quorum():
        status_set('active', 'Unit is ready and clustered')
    else:
        # Unit should be running and clustered, but no quorum
        # TODO: should this be blocked or waiting?
        status_set('blocked', 'Unit not clustered (no quorum)')
        # If there's a pending lock for this unit,
        # can i get the lock?
        # reboot the ceph-mon process


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status()
