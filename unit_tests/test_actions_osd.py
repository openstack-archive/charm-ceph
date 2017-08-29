# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mock import mock, mock_open
import sys

from test_utils import CharmTestCase

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
mock_apt = mock.MagicMock()
sys.modules['apt'] = mock_apt
mock_apt.apt_pkg = mock.MagicMock()

# mocking for rados
mock_rados = mock.MagicMock()
sys.modules['rados'] = mock_rados
mock_rados.connect = mock.MagicMock()

# mocking for psutil
mock_psutil = mock.MagicMock()
sys.modules['psutil'] = mock_psutil
mock_psutil.disks = mock.MagicMock()

with mock.patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    # import health actions as actions
    import ceph_ops as actions


class OpsTestCase(CharmTestCase):

    def setUp(self):
        super(OpsTestCase, self).setUp(
            actions, ["check_output",
                      "action_get",
                      "action_fail",
                      "open"])

    def test_get_health(self):
        actions.get_health()
        cmd = ['ceph', 'health']
        self.check_output.assert_called_once_with(cmd)

    def test_get_osd_for_disk(self):

        # mock action_get and the disk_partion list
        # to redirect calls to act on non-existent
        # mount points
        self.action_get.return_value = '/dev/null'
        mock_psutil.disk_partitions.return_value = dict({
            '/dev/null': '/mnt'
        })

        # test first for failure. because we've mocked
        # disk_partitions, we're acting on a nonexistent
        # mountpoint/device combo, so the action should file
        # as this path will certainly not be a Ceph OSD
        actions.osd_for_disk()
        self.action_fail.assert_called_once

        # now, mock open so that we can force the action to
        # succeed, and measure that the read call was made
        # in response to the open succeeding as a measure of
        # success
        mocked_open = mock_open(read_data='3\n')
        mock.patch('self.open', mocked_open, create=True)
        actions.osd_for_disk()
        self.assertEqual(self.action_get.call_count, 2)
        self.assertEqual(self.open.call_count, 2)
        self.open.assert_called_with('/mnt/whoami', 'r')
        self.open.read.assert_called_once

    def test_get_disk_for_osd(self):
        with mock.patch('os.stat') as mocked_stat:
            self.action_get.return_value = '1'
            actions.disk_for_osd()
            mocked_stat.assert_called_once_with('/var/lib/ceph/osd/ceph-1')

    def test_list_host_osds(self):
        with mock.patch('glob.glob') as mocked_glob:
            mocked_glob.return_value = [
                '/var/lib/ceph/osd/ceph-0', 
                '/var/lib/ceph/osd/ceph-1', 
                '/var/lib/ceph/osd/ceph-2',
            ]
            actions.list_host_osds()
            mocked_glob.assert_called_once_with(
                '/var/lib/ceph/osd/ceph-[0-9]+'
            )
            self.assertEqual(len(mocked_glob.return_value), 3)
