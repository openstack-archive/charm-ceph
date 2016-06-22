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

import time

from mock import patch, call, MagicMock
import sys

sys.path.append('/home/chris/repos/ceph-mon/hooks')

import test_utils

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    import ceph_hooks

TO_PATCH = [
    'hookenv',
    'status_set',
    'config',
    'ceph',
    'log',
    'add_source',
    'apt_update',
    'apt_install',
    'service_stop',
    'service_start',
    'host',
]


def config_side_effect(*args):
    if args[0] == 'source':
        return 'cloud:trusty-kilo'
    elif args[0] == 'key':
        return 'key'
    elif args[0] == 'release-version':
        return 'cloud:trusty-kilo'


previous_node_start_time = time.time() - (9 * 60)


def monitor_key_side_effect(*args):
    if args[1] == \
            'ip-192-168-1-2_done':
        return False
    elif args[1] == \
            'ip-192-168-1-2_start':
        # Return that the previous node started 9 minutes ago
        return previous_node_start_time


class UpgradeRollingTestCase(test_utils.CharmTestCase):
    def setUp(self):
        super(UpgradeRollingTestCase, self).setUp(ceph_hooks, TO_PATCH)

    @patch('ceph_hooks.roll_monitor_cluster')
    def test_check_for_upgrade(self, roll_monitor_cluster):
        self.host.lsb_release.return_value = {
            'DISTRIB_CODENAME': 'trusty',
        }
        previous_mock = MagicMock().return_value
        previous_mock.previous.return_value = "cloud:trusty-juno"
        self.hookenv.config.side_effect = [previous_mock,
                                           config_side_effect('source')]
        ceph_hooks.check_for_upgrade()

        roll_monitor_cluster.assert_called_with('cloud:trusty-kilo')

    @patch('ceph_hooks.upgrade_monitor')
    @patch('ceph_hooks.monitor_key_set')
    def test_lock_and_roll(self, monitor_key_set, upgrade_monitor):
        monitor_key_set.monitor_key_set.return_value = None
        ceph_hooks.lock_and_roll(my_name='ip-192-168-1-2')
        upgrade_monitor.assert_called_once_with()

    def test_upgrade_monitor(self):
        self.config.side_effect = config_side_effect
        self.ceph.get_version.return_value = "0.80"
        self.ceph.systemd.return_value = False
        ceph_hooks.upgrade_monitor()
        self.service_stop.assert_called_with('ceph-mon-all')
        self.service_start.assert_called_with('ceph-mon-all')
        self.status_set.assert_has_calls([
            call('maintenance', 'Upgrading monitor'),
            call('active', '')
        ])

    @patch('ceph_hooks.lock_and_roll')
    @patch('ceph_hooks.wait_on_previous_node')
    @patch('ceph_hooks.get_mon_map')
    @patch('ceph_hooks.socket')
    def test_roll_monitor_cluster_second(self,
                                         socket,
                                         get_mon_map,
                                         wait_on_previous_node,
                                         lock_and_roll):
        wait_on_previous_node.return_value = None
        socket.gethostname.return_value = "ip-192-168-1-3"
        get_mon_map.return_value = {
            'monmap': {
                'mons': [
                    {
                        'name': 'ip-192-168-1-2',
                    },
                    {
                        'name': 'ip-192-168-1-3',
                    },
                ]
            }
        }
        ceph_hooks.roll_monitor_cluster('0.94.1')
        self.status_set.assert_called_with(
            'blocked',
            'Waiting on ip-192-168-1-2 to finish upgrading')
        lock_and_roll.assert_called_with(my_name="ip-192-168-1-3")

    @patch.object(ceph_hooks, 'time')
    @patch('ceph_hooks.monitor_key_get')
    @patch('ceph_hooks.monitor_key_exists')
    def test_wait_on_previous_node(self, monitor_key_exists, monitor_key_get,
                                   mock_time):
        tval = [previous_node_start_time]

        def fake_time():
            tval[0] += 100
            return tval[0]

        mock_time.time.side_effect = fake_time
        monitor_key_get.side_effect = monitor_key_side_effect
        monitor_key_exists.return_value = False

        ceph_hooks.wait_on_previous_node("ip-192-168-1-2")

        # Make sure we checked to see if the previous node started
        monitor_key_get.assert_has_calls(
            [call('admin', 'ip-192-168-1-2_start')]
        )
        # Make sure we checked to see if the previous node was finished
        monitor_key_exists.assert_has_calls(
            [call('admin', 'ip-192-168-1-2_done')]
        )
        # Make sure we waited at last once before proceeding
        self.log.assert_has_calls(
            [call('Previous node is: ip-192-168-1-2')],
            [call('ip-192-168-1-2 is not finished. Waiting')],
        )
        self.assertEqual(tval[0], previous_node_start_time + 700)
