import mock
import test_utils


with mock.patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
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
    def test_check_charm_func_no_peers(self, _peer_units):
        _peer_units.return_value = NO_PEERS
        stat, _ = hooks.check_charm_func()
        assert stat == 'blocked'

    @mock.patch.object(hooks, 'get_peer_units')
    def test_check_charm_func_peers_incomplete(self, _peer_units):
        _peer_units.return_value = ENOUGH_PEERS_INCOMPLETE
        stat, _ = hooks.check_charm_func()
        assert stat == 'waiting'

    @mock.patch.object(hooks, 'get_peer_units')
    def test_check_charm_func_peers_complete_active(self, _peer_units):
        _peer_units.return_value = ENOUGH_PEERS_COMPLETE
        self.ceph.is_bootstrapped.return_value = True
        self.ceph.is_quorum.return_value = True
        stat, _ = hooks.check_charm_func()
        assert stat == 'active'

    @mock.patch.object(hooks, 'get_peer_units')
    def test_check_charm_func_peers_complete_down(self, _peer_units):
        _peer_units.return_value = ENOUGH_PEERS_COMPLETE
        self.ceph.is_bootstrapped.return_value = False
        self.ceph.is_quorum.return_value = False
        stat, _ = hooks.check_charm_func()
        assert stat == 'blocked'

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

    def test_assess_status(self):
        with mock.patch.object(hooks, 'assess_status_func') as asf:
            callee = mock.MagicMock()
            asf.return_value = callee
            hooks.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()

    @mock.patch.object(hooks, 'REQUIRED_INTERFACES')
    @mock.patch.object(hooks, 'make_assess_status_func')
    def test_assess_status_func(self,
                                make_assess_status_func,
                                REQUIRED_INTERFACES):
        hooks.assess_status_func('test-config')
        # ports=None whilst port checks are disabled.
        make_assess_status_func.assert_called_once_with(
            'test-config',
            REQUIRED_INTERFACES,
            charm_func=mock.ANY,
            services=None,
            ports=None)

    def test_pause_unit_helper(self):
        with mock.patch.object(hooks, '_pause_resume_helper') as prh:
            hooks.pause_unit_helper('random-config')
            prh.assert_called_once_with(hooks.pause_unit, 'random-config')
        with mock.patch.object(hooks, '_pause_resume_helper') as prh:
            hooks.resume_unit_helper('random-config')
            prh.assert_called_once_with(hooks.resume_unit, 'random-config')

    def test_pause_resume_helper(self):
        f = mock.MagicMock()
        with mock.patch.object(hooks, 'assess_status_func') as asf:
            asf.return_value = 'assessor'
            hooks._pause_resume_helper(f, 'some-config')
            asf.assert_called_once_with('some-config')
            # ports=None whilst port checks are disabled.
            f.assert_called_once_with('assessor', services=None, ports=None)
