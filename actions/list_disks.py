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

"""
List unmounted devices.

This script will get all block devices known by udev and check if they
are mounted so that we can give unmounted devices to the administrator.
"""

import pyudev
import sys


sys.path.append('hooks/')

from charmhelpers.contrib.storage.linux.utils import is_device_mounted
from charmhelpers.core.hookenv import log, action_set


if __name__ == '__main__':
    disks = []
    context = pyudev.Context()
    for device in context.list_devices(DEVTYPE='disk'):
        if device['SUBSYSTEM'] == 'block':
            matched = False
            for block_type in [u'dm', u'loop', u'ram', u'nbd']:
                if block_type in device.device_node:
                    matched = True
            if matched:
                continue
            disks.append(device.device_node)
    log("Found disks: {}".format(disks))
    unmounted_disks = [disk for disk in disks if not is_device_mounted(disk)]

    action_set({
        'disks': unmounted_disks})
