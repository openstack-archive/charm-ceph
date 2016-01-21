import json
import unittest

import mock

import ceph_broker


class CephBrokerTestCase(unittest.TestCase):
    def setUp(self):
        super(CephBrokerTestCase, self).setUp()

    @mock.patch('ceph_broker.log')
    def test_process_requests_noop(self, mock_log):
        req = json.dumps({'api-version': 1, 'ops': []})
        rc = ceph_broker.process_requests(req)
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.log')
    def test_process_requests_missing_api_version(self, mock_log):
        req = json.dumps({'ops': []})
        rc = ceph_broker.process_requests(req)
        self.assertEqual(json.loads(rc), {'exit-code': 1,
                                          'stderr':
                                              ('Missing or invalid api version '
                                               '(None)')})

    @mock.patch('ceph_broker.log')
    def test_process_requests_invalid_api_version(self, mock_log):
        req = json.dumps({'api-version': 2, 'ops': []})
        rc = ceph_broker.process_requests(req)
        print "Return: %s" % rc
        self.assertEqual(json.loads(rc),
                         {'exit-code': 1,
                          'stderr': 'Missing or invalid api version (2)'})

    @mock.patch('ceph_broker.log')
    def test_process_requests_invalid(self, mock_log):
        reqs = json.dumps({'api-version': 1, 'ops': [{'op': 'invalid_op'}]})
        rc = ceph_broker.process_requests(reqs)
        self.assertEqual(json.loads(rc),
                         {'exit-code': 1,
                          'stderr': "Unknown operation 'invalid_op'"})

    @mock.patch('ceph_broker.create_pool')
    @mock.patch('ceph_broker.pool_exists')
    @mock.patch('ceph_broker.log')
    def test_process_requests_create_pool(self, mock_log, mock_pool_exists,
                                          mock_create_pool):
        mock_pool_exists.return_value = False
        reqs = json.dumps({'api-version': 1,
                           'ops': [{'op': 'create-pool', 'name':
                               'foo', 'replicas': 3}]})
        rc = ceph_broker.process_requests(reqs)
        mock_pool_exists.assert_called_with(service='admin', name='foo')
        mock_create_pool.assert_called_with(service='admin', name='foo',
                                            replicas=3)
        self.assertEqual(json.loads(rc), {'exit-code': 0})

    @mock.patch('ceph_broker.create_pool')
    @mock.patch('ceph_broker.pool_exists')
    @mock.patch('ceph_broker.log')
    def test_process_requests_create_erasure_pool(self, mock_log,
                                                  mock_pool_exists,
                                                  mock_create_pool):
        mock_pool_exists.return_value = False
        reqs = json.dumps({'api-version': 1,
                           'ops': [{'op': 'create-pool',
                                    'name': 'foo',
                                    'erasure-type': 'jerasure',
                                    'failure-domain': 'host',
                                    'k': 3,
                                    'm': 2}]})
        rc = ceph_broker.process_requests(reqs)
        mock_pool_exists.assert_called_with(service='admin', name='foo')
        mock_create_pool.assert_called_with(service='admin', name='foo')
        self.assertEqual(json.loads(rc), {'exit-code': 0})


'''
        elif op == "create-cache-tier":
            handle_create_cache_tier(request=req, service=svc)
        elif op == "remove-cache-tier":
            handle_remove_cache_tier(request=req, service=svc)
        elif op == "create-erasure-profile":
            handle_create_erasure_profile(request=req, service=svc)
        elif op == "delete-pool":
            pool = req.get('name')
            delete_pool(service=svc, name=pool)
        elif op == "rename-pool":
            old_name = req.get('name')
            new_name = req.get('new-name')
            rename_pool(service=svc, old_name=old_name, new_name=new_name)
        elif op == "snapshot-pool":
            pool = req.get('name')
            snapshot_name = req.get('snapshot-name')
            snapshot_pool(service=svc, pool_name=pool,
                          snapshot_name=snapshot_name)
        elif op == "remove-pool-snapshot":
            pool = req.get('name')
            snapshot_name = req.get('snapshot-name')
            remove_pool_snapshot(service=svc, pool_name=pool,
                                 snapshot_name=snapshot_name)
        elif op == "set-pool-value":
            handle_set_pool_value(request=req, service=svc)
'''


@mock.patch('ceph_broker.create_pool')
@mock.patch('ceph_broker.pool_exists')
@mock.patch('ceph_broker.log')
def test_process_requests_create_pool_exists(self, mock_log,
                                             mock_pool_exists,
                                             mock_create_pool):
    mock_pool_exists.return_value = True
    reqs = json.dumps({'api-version': 1,
                       'ops': [{'op': 'create-pool', 'name': 'foo',
                                'replicas': 3}]})
    rc = ceph_broker.process_requests(reqs)
    mock_pool_exists.assert_called_with(service='admin', name='foo')
    self.assertFalse(mock_create_pool.called)
    self.assertEqual(json.loads(rc), {'exit-code': 0})


@mock.patch('ceph_broker.create_pool')
@mock.patch('ceph_broker.pool_exists')
@mock.patch('ceph_broker.log')
def test_process_requests_create_pool_rid(self, mock_log, mock_pool_exists,
                                          mock_create_pool):
    mock_pool_exists.return_value = False
    reqs = json.dumps({'api-version': 1,
                       'request-id': '1ef5aede',
                       'ops': [{'op': 'create-pool', 'name':
                           'foo', 'replicas': 3}]})
    rc = ceph_broker.process_requests(reqs)
    mock_pool_exists.assert_called_with(service='admin', name='foo')
    mock_create_pool.assert_called_with(service='admin', name='foo',
                                        replicas=3)
    self.assertEqual(json.loads(rc)['exit-code'], 0)
    self.assertEqual(json.loads(rc)['request-id'], '1ef5aede')


@mock.patch('ceph_broker.log')
def test_process_requests_invalid_api_rid(self, mock_log):
    reqs = json.dumps({'api-version': 0, 'request-id': '1ef5aede',
                       'ops': [{'op': 'create-pool'}]})
    rc = ceph_broker.process_requests(reqs)
    self.assertEqual(json.loads(rc)['exit-code'], 1)
    self.assertEqual(json.loads(rc)['stderr'],
                     "Missing or invalid api version (0)")
    self.assertEqual(json.loads(rc)['request-id'], '1ef5aede')
