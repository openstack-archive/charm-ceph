__author__ = 'chris'

import json
import mock
import unittest


with mock.patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    from hooks import ceph_broker


class TestCephOps(unittest.TestCase):
    """
    @mock.patch('ceph_broker.log')
    def test_connect(self, mock_broker):
        self.fail()
    """

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.create_erasure_profile')
    def test_create_erasure_profile(self, mock_create_erasure, mock_log):
        req = json.dumps({'api-version': 1,
                          'ops': [{
                              'op': 'create-erasure-profile',
                              'name': 'foo',
                              'erasure-type': 'jerasure',
                              'failure-domain': 'rack',
                              'k': 3,
                              'm': 2,
                          }]})
        rc = ceph_broker.process_requests(req)
        mock_create_erasure.assert_called_with(service='admin',
                                               profile_name='foo',
                                               coding_chunks=2,
                                               data_chunks=3,
                                               locality=None,
                                               failure_domain='rack',
                                               erasure_plugin_name='jerasure')
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.pool_exists')
    @mock.patch('hooks.ceph_broker.ReplicatedPool.create')
    def test_process_requests_create_replicated_pool(self,
                                                     mock_replicated_pool,
                                                     mock_pool_exists,
                                                     mock_log):
        mock_pool_exists.return_value = False
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'create-pool',
                               'pool-type': 'replicated',
                               'name': 'foo',
                               'replicas': 3
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_pool_exists.assert_called_with(service='admin', name='foo')
        mock_replicated_pool.assert_called_with()
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.delete_pool')
    def test_process_requests_delete_pool(self,
                                          mock_delete_pool,
                                          mock_log):
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'delete-pool',
                               'name': 'foo',
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_delete_pool.assert_called_with(service='admin', name='foo')
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.pool_exists')
    @mock.patch('hooks.ceph_broker.ErasurePool.create')
    @mock.patch('hooks.ceph_broker.erasure_profile_exists')
    def test_process_requests_create_erasure_pool(self, mock_profile_exists,
                                                  mock_erasure_pool,
                                                  mock_pool_exists,
                                                  mock_log):
        mock_pool_exists.return_value = False
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'create-pool',
                               'pool-type': 'erasure',
                               'name': 'foo',
                               'erasure-profile': 'default'
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_profile_exists.assert_called_with(service='admin', name='default')
        mock_pool_exists.assert_called_with(service='admin', name='foo')
        mock_erasure_pool.assert_called_with()
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.pool_exists')
    @mock.patch('hooks.ceph_broker.Pool.add_cache_tier')
    def test_process_requests_create_cache_tier(self, mock_pool,
                                                mock_pool_exists, mock_log):
        mock_pool_exists.return_value = True
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'create-cache-tier',
                               'cold-pool': 'foo',
                               'hot-pool': 'foo-ssd',
                               'mode': 'writeback',
                               'erasure-profile': 'default'
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_pool_exists.assert_any_call(service='admin', name='foo')
        mock_pool_exists.assert_any_call(service='admin', name='foo-ssd')

        mock_pool.assert_called_with(cache_pool='foo-ssd', mode='writeback')
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.pool_exists')
    @mock.patch('hooks.ceph_broker.Pool.remove_cache_tier')
    def test_process_requests_remove_cache_tier(self, mock_pool,
                                                mock_pool_exists, mock_log):
        mock_pool_exists.return_value = True
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'remove-cache-tier',
                               'hot-pool': 'foo-ssd',
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_pool_exists.assert_any_call(service='admin', name='foo-ssd')

        mock_pool.assert_called_with(cache_pool='foo-ssd')
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.snapshot_pool')
    def test_snapshot_pool(self, mock_snapshot_pool, mock_log):
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'snapshot-pool',
                               'name': 'foo',
                               'snapshot-name': 'foo-snap1',
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_snapshot_pool.return_value = 1
        mock_snapshot_pool.assert_called_with(service='admin',
                                              pool_name='foo',
                                              snapshot_name='foo-snap1')
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.rename_pool')
    def test_rename_pool(self, mock_rename_pool, mock_log):
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'rename-pool',
                               'name': 'foo',
                               'new-name': 'foo2',
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_rename_pool.assert_called_with(service='admin',
                                            old_name='foo',
                                            new_name='foo2')
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.remove_pool_snapshot')
    def test_remove_pool_snapshot(self, mock_snapshot_pool, mock_broker):
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'remove-pool-snapshot',
                               'name': 'foo',
                               'snapshot-name': 'foo-snap1',
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_snapshot_pool.assert_called_with(service='admin',
                                              pool_name='foo',
                                              snapshot_name='foo-snap1')
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    @mock.patch('hooks.ceph_broker.pool_set')
    def test_set_pool_value(self, mock_set_pool, mock_broker):
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'set-pool-value',
                               'name': 'foo',
                               'key': 'size',
                               'value': 3,
                           }]})
        rc = ceph_broker.process_requests(reqs)
        mock_set_pool.assert_called_with(service='admin',
                                         pool_name='foo',
                                         key='size',
                                         value=3)
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    def test_set_invalid_pool_value(self, mock_broker):
        reqs = json.dumps({'api-version': 1,
                           'ops': [{
                               'op': 'set-pool-value',
                               'name': 'foo',
                               'key': 'size',
                               'value': 'abc',
                           }]})
        rc = ceph_broker.process_requests(reqs)
        # self.assertRaises(AssertionError)
        self.assertEqual(json.loads(rc)['exit-code'], 1)

    '''
    @mock.patch('ceph_broker.log')
    def test_set_pool_max_bytes(self, mock_broker):
        self.fail()
    '''


if __name__ == '__main__':
    unittest.main()
