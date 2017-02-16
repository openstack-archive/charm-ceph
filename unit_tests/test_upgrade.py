import unittest

__author__ = 'Chris Holcombe <chris.holcombe@canonical.com>'

from mock import patch, MagicMock, call

from ceph_hooks import check_for_upgrade


def config_side_effect(*args):
    if args[0] == 'source':
        return 'cloud:trusty-kilo'
    elif args[0] == 'key':
        return 'key'
    elif args[0] == 'release-version':
        return 'cloud:trusty-kilo'


class UpgradeRollingTestCase(unittest.TestCase):

    @patch('ceph_hooks.ceph.is_bootstrapped')
    @patch('ceph_hooks.log')
    @patch('ceph_hooks.ceph.roll_monitor_cluster')
    @patch('ceph_hooks.ceph.wait_for_all_monitors_to_upgrade')
    @patch('ceph_hooks.hookenv')
    @patch('ceph_hooks.host')
    @patch('ceph_hooks.ceph.roll_osd_cluster')
    def test_check_for_upgrade(self,
                               roll_osd_cluster,
                               host,
                               hookenv,
                               wait_for_mons,
                               roll_monitor_cluster,
                               log,
                               is_bootstrapped):
        is_bootstrapped.return_value = True
        host.lsb_release.return_value = {
            'DISTRIB_CODENAME': 'trusty',
        }
        previous_mock = MagicMock().return_value
        previous_mock.previous.return_value = "cloud:trusty-juno"
        hookenv.config.side_effect = [previous_mock,
                                      config_side_effect('source')]
        check_for_upgrade()

        wait_for_mons.assert_called_with(
            new_version='cloud:trusty-kilo',
            upgrade_key='admin'
        )
        roll_osd_cluster.assert_called_with(
            new_version='cloud:trusty-kilo',
            upgrade_key='admin'
        )

        roll_monitor_cluster.assert_called_with(
            new_version='cloud:trusty-kilo',
            upgrade_key='admin'
        )
        log.assert_has_calls(
            [
                call('old_version: cloud:trusty-juno'),
                call('new_version: cloud:trusty-kilo'),
                call('cloud:trusty-juno to cloud:trusty-kilo is a valid '
                     'upgrade path.  Proceeding.')
            ]
        )

    @patch('ceph_hooks.ceph.is_bootstrapped')
    @patch('ceph_hooks.log')
    @patch('ceph_hooks.ceph.roll_monitor_cluster')
    @patch('ceph_hooks.ceph.wait_for_all_monitors_to_upgrade')
    @patch('ceph_hooks.hookenv')
    @patch('ceph_hooks.host')
    @patch('ceph_hooks.ceph.roll_osd_cluster')
    def test_check_for_upgrade_not_bootstrapped(self,
                                                roll_osd_cluster,
                                                host,
                                                hookenv,
                                                wait_for_mons,
                                                roll_monitor_cluster,
                                                log,
                                                is_bootstrapped):
        is_bootstrapped.return_value = False
        host.lsb_release.return_value = {
            'DISTRIB_CODENAME': 'trusty',
        }
        previous_mock = MagicMock().return_value
        previous_mock.previous.return_value = "cloud:trusty-juno"
        hookenv.config.side_effect = [previous_mock,
                                      config_side_effect('source')]
        check_for_upgrade()

        roll_osd_cluster.assert_not_called()

        roll_monitor_cluster.assert_not_called()
