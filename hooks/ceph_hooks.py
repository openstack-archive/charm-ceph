#!/usr/bin/python

#
# Copyright 2012 Canonical Ltd.
#
# Authors:
#  Paul Collins <paul.collins@canonical.com>
#  James Page <james.page@ubuntu.com>
#

import glob
import os
import shutil
import sys

import ceph
from charmhelpers.core.hookenv import (
    log,
    DEBUG,
    ERROR,
    config,
    relation_ids,
    related_units,
    relation_get,
    relation_set,
    remote_unit,
    Hooks, UnregisteredHookError,
    service_name,
    relations_of_type,
    status_set,
    local_unit,
    storage_get,
    storage_list
)
from charmhelpers.core.host import (
    service_restart,
    umount,
    mkdir,
    write_file,
    rsync,
    cmp_pkgrevno
)
from charmhelpers.fetch import (
    apt_install,
    apt_update,
    filter_installed_packages,
    add_source
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.openstack.alternatives import install_alternative
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr,
    format_ipv6_addr,
)
from charmhelpers.core.sysctl import create as create_sysctl
from charmhelpers.core.templating import render

from utils import (
    get_networks,
    get_public_addr,
    assert_charm_supports_ipv6
)
from ceph_broker import (
    process_requests
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden
from charmhelpers.contrib.openstack.utils import (
    pause_unit,
    resume_unit,
    make_assess_status_func,
    is_unit_paused_set,
)

hooks = Hooks()

# NOTE(ajkavanagh) - this is for the new pause/resume maintenance mode
# functionality and can be used later to enforce interface checks.
REQUIRED_INTERFACES = {
}

NAGIOS_PLUGINS = '/usr/local/lib/nagios/plugins'
SCRIPTS_DIR = '/usr/local/bin'
STATUS_FILE = '/var/lib/nagios/cat-ceph-status.txt'
STATUS_CRONFILE = '/etc/cron.d/cat-ceph-health'


def install_upstart_scripts():
    # Only install upstart configurations for older versions
    if cmp_pkgrevno('ceph', "0.55.1") < 0:
        for x in glob.glob('files/upstart/*.conf'):
            shutil.copy(x, '/etc/init/')


@hooks.hook('install.real')
@harden()
def install():
    execd_preinstall()
    add_source(config('source'), config('key'))
    apt_update(fatal=True)
    apt_install(packages=ceph.PACKAGES, fatal=True)
    install_upstart_scripts()


def emit_cephconf():
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
    }

    if config('prefer-ipv6'):
        dynamic_ipv6_address = get_ipv6_addr()[0]
        if not public_network:
            cephcontext['public_addr'] = dynamic_ipv6_address
        if not cluster_network:
            cephcontext['cluster_addr'] = dynamic_ipv6_address

    # Install ceph.conf as an alternative to support
    # co-existence with other charms that write this file
    charm_ceph_conf = "/var/lib/charm/{}/ceph.conf".format(service_name())
    mkdir(os.path.dirname(charm_ceph_conf), owner=ceph.ceph_user(),
          group=ceph.ceph_user())
    render('ceph.conf', charm_ceph_conf, cephcontext, perms=0o644)
    install_alternative('ceph.conf', '/etc/ceph/ceph.conf',
                        charm_ceph_conf, 100)

JOURNAL_ZAPPED = '/var/lib/ceph/journal_zapped'


@hooks.hook('config-changed')
@harden()
def config_changed():
    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

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
    if (not ceph.is_bootstrapped() and int(config('monitor-count')) == 1):
        status_set('maintenance', 'Bootstrapping single Ceph MON')
        ceph.bootstrap_monitor_cluster(config('monitor-secret'))
        ceph.wait_for_bootstrap()

    storage_changed()

    if relations_of_type('nrpe-external-master'):
        update_nrpe_config()


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
    '''
    Returns a dictionary of unit names from the mon peer relation with
    a flag indicating whether the unit has presented its address
    '''
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
    if config('osd-devices'):
        devices = [
            os.path.realpath(path)
            for path in config('osd-devices').split(' ')]
    else:
        devices = []
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
                     relation_settings={'ceph-public-address':
                                        public_addr})


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


def upgrade_keys():
    ''' Ceph now required mon allow rw for pool creation '''
    if len(relation_ids('radosgw')) > 0:
        ceph.upgrade_key_caps('client.radosgw.gateway',
                              ceph._radosgw_caps)
    for relid in relation_ids('client'):
        units = related_units(relid)
        if len(units) > 0:
            service_name = units[0].split('/')[0]
            ceph.upgrade_key_caps('client.{}'.format(service_name),
                                  ceph._default_caps)


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
    """Process broker request(s)."""
    if ceph.is_quorum():
        settings = relation_get(rid=relid, unit=unit)
        if 'broker_req' in settings:
            if not ceph.is_leader():
                log("Not leader - ignoring broker request", level=DEBUG)
            else:
                rsp = process_requests(settings['broker_req'])
                unit_id = unit.replace('/', '-')
                unit_response_key = 'broker-rsp-' + unit_id
                log('mon cluster in quorum - providing radosgw with keys')
                public_addr = get_public_addr()
                data = {
                    'fsid': config('fsid'),
                    'radosgw_key': ceph.get_radosgw_key(),
                    'auth': config('auth-supported'),
                    'ceph-public-address': public_addr,
                    unit_response_key: rsp,
                }
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


@hooks.hook('upgrade-charm')
@harden()
def upgrade_charm():
    emit_cephconf()
    apt_install(packages=filter_installed_packages(ceph.PACKAGES), fatal=True)
    install_upstart_scripts()
    ceph.update_monfs()
    upgrade_keys()
    mon_relation_joined()


@hooks.hook('start')
def start():
    # In case we're being redeployed to the same machines, try
    # to make sure everything is running as soon as possible.
    # BUT only if the unit is not in maintenance mode
    if not is_unit_paused_set():
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
    apt_install('python-dbus')
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


def check_charm_func():
    """Assess status of current unit

    @return (state, message) - strings representing custom state of unit
    """
    moncount = int(config('monitor-count'))
    units = get_peer_units()
    # not enough peers and mon_count > 1
    if len(units.keys()) < moncount:
        return ('blocked',
                'Insufficient peer units to bootstrap'
                ' cluster (require {})'.format(moncount))

    # mon_count > 1, peers, but no ceph-public-address
    ready = sum(1 for unit_ready in units.itervalues() if unit_ready)
    if ready < moncount:
        return ('waiting', 'Peer units detected, waiting for addresses')

    # active - bootstrapped + quorum status check
    if ceph.is_bootstrapped() and ceph.is_quorum():
        return ('active', 'Unit is ready and clustered')
    else:
        # Unit should be running and clustered, but no quorum
        # TODO: should this be blocked or waiting?
        return ('blocked', 'Unit not clustered (no quorum)')


class FakeOSConfigRenderer(object):
    """This class is to provide to register_configs() as a 'fake'
    OSConfigRenderer object that has a complete_contexts method that returns
    an empty list.  This is so that the pause/resume framework can be used
    from charmhelpers that requires configs to be able to run.
    This is a bit of a hack, but via Python's duck-typing enables the function
    to work.
    """
    def complete_contexts(self):
        return []


def register_configs():
    """Return a OSConfigRenderer object.
    However, ceph-mon wasn't written using OSConfigRenderer objects to do the
    config files, so this just returns an empty OSConfigRenderer object.

    @returns empty FakeOSConfigRenderer object.
    """
    return FakeOSConfigRenderer()


def assess_status(configs):
    """Assess status of current unit
    Decides what the state of the unit should be based on the current
    configuration.
    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    assess_status_func(configs)()


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE(ajkavanagh) ports are not checked due to race hazards with services
    that don't behave sychronously w.r.t their service scripts.  e.g.
    apache2.
    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    # Note 'odd' lambda is needed as charm_func takes configs, but
    # charm_check_func() doesn't need them (and thus would make the function
    # look more complex).
    return make_assess_status_func(
        configs, REQUIRED_INTERFACES,
        charm_func=lambda _: check_charm_func(),
        services=None, ports=None)


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit
    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=None,
      ports=None)


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status(register_configs())
