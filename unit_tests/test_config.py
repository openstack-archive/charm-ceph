import os
import shutil
import tempfile

import test_utils

from mock import patch


with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    import ceph_hooks as hooks

TO_PATCH = [
    'config',
]


class GetDevicesTestCase(test_utils.CharmTestCase):

    def setUp(self):
        super(GetDevicesTestCase, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp_dir)

    def test_get_devices_empty(self):
        """
        If osd-devices is set to an empty string, get_devices() returns
        an empty list.
        """
        self.test_config.set("osd-devices", "")
        self.assertEqual([], hooks.get_devices())

    def test_get_devices_non_existing_files(self):
        """
        If osd-devices points to a file that doesn't exist, it's still
        returned by get_devices().
        """
        non_existing = os.path.join(self.tmp_dir, "no-such-file")
        self.test_config.set("osd-devices", non_existing)
        self.assertEqual([non_existing], hooks.get_devices())

    def test_get_devices_multiple(self):
        """
        Multiple devices can be specified in osd-devices by separating
        them with spaces.
        """
        device1 = os.path.join(self.tmp_dir, "device1")
        device2 = os.path.join(self.tmp_dir, "device2")
        self.test_config.set("osd-devices", "{} {}".format(device1, device2))
        self.assertEqual([device1, device2], hooks.get_devices())

    def test_get_devices_symlink(self):
        """
        If a symlink is specified in osd-devices, get_devices() resolves
        it and returns the link target.
        """
        device = os.path.join(self.tmp_dir, "device")
        link = os.path.join(self.tmp_dir, "link")
        os.symlink(device, link)
        self.test_config.set("osd-devices", link)
        self.assertEqual([device], hooks.get_devices())
