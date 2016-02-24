import mock
import test_utils

import ceph_hooks as hooks

TO_PATCH = [
    'status_set',
    'config',
    'ceph',
    'relation_ids',
    'relation_get',
    'related_units',
    'local_unit',
]

NO_PEERS = {
    'ceph-mon1': True
}

ENOUGH_PEERS_INCOMPLETE = {
    'ceph-mon1': True,
    'ceph-mon2': False,
    'ceph-mon3': False,
}

ENOUGH_PEERS_COMPLETE = {
    'ceph-mon1': True,
    'ceph-mon2': True,
    'ceph-mon3': True,
}


class ServiceStatusTestCase(test_utils.CharmTestCase):
    def setUp(self):
        super(ServiceStatusTestCase, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.test_config.set('monitor-count', 3)
        self.local_unit.return_value = 'ceph-mon1'

    @mock.patch.object(hooks, 'get_peer_units')
    def test_assess_status_no_peers(self, _peer_units):
        _peer_units.return_value = NO_PEERS
        hooks.assess_status()
        self.status_set.assert_called_with('blocked', mock.ANY)

    @mock.patch.object(hooks, 'get_peer_units')
    def test_assess_status_peers_incomplete(self, _peer_units):
        _peer_units.return_value = ENOUGH_PEERS_INCOMPLETE
        hooks.assess_status()
        self.status_set.assert_called_with('waiting', mock.ANY)

    @mock.patch.object(hooks, 'get_peer_units')
    def test_assess_status_peers_complete_active(self, _peer_units):
        _peer_units.return_value = ENOUGH_PEERS_COMPLETE
        self.ceph.is_bootstrapped.return_value = True
        self.ceph.is_quorum.return_value = True
        hooks.assess_status()
        self.status_set.assert_called_with('active', mock.ANY)

    @mock.patch.object(hooks, 'get_peer_units')
    def test_assess_status_peers_complete_down(self, _peer_units):
        _peer_units.return_value = ENOUGH_PEERS_COMPLETE
        self.ceph.is_bootstrapped.return_value = False
        self.ceph.is_quorum.return_value = False
        hooks.assess_status()
        self.status_set.assert_called_with('blocked', mock.ANY)

    def test_get_peer_units_no_peers(self):
        self.relation_ids.return_value = ['mon:1']
        self.related_units.return_value = []
        self.assertEquals({'ceph-mon1': True},
                          hooks.get_peer_units())

    def test_get_peer_units_peers_incomplete(self):
        self.relation_ids.return_value = ['mon:1']
        self.related_units.return_value = ['ceph-mon2',
                                           'ceph-mon3']
        self.relation_get.return_value = None
        self.assertEquals({'ceph-mon1': True,
                           'ceph-mon2': False,
                           'ceph-mon3': False},
                          hooks.get_peer_units())

    def test_get_peer_units_peers_complete(self):
        self.relation_ids.return_value = ['mon:1']
        self.related_units.return_value = ['ceph-mon2',
                                           'ceph-mon3']
        self.relation_get.side_effect = ['ceph-mon2',
                                         'ceph-mon3']
        self.assertEquals({'ceph-mon1': True,
                           'ceph-mon2': True,
                           'ceph-mon3': True},
                          hooks.get_peer_units())
