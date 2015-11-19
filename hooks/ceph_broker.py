#!/usr/bin/python
#
# Copyright 2014 Canonical Ltd.
#
import json

from charmhelpers.core.hookenv import (
    log,
    DEBUG,
    INFO,
    ERROR,
)
from charmhelpers.contrib.storage.linux.ceph import (
    create_pool,
    pool_exists,
)


def decode_req_encode_rsp(f):
    """Decorator to decode incoming requests and encode responses."""
    def decode_inner(req):
        return json.dumps(f(json.loads(req)))

    return decode_inner


@decode_req_encode_rsp
def process_requests(reqs):
    """Process Ceph broker request(s).

    This is a versioned api. API version must be supplied by the client making
    the request.
    """
    request_id = reqs.get('request-id')
    try:
        version = reqs.get('api-version')
        if version == 1:
            log('Processing request {}'.format(request_id), level=DEBUG)
            resp = process_requests_v1(reqs['ops'])
            if request_id:
                resp['request-id'] = request_id

            return resp

    except Exception as exc:
        log(str(exc), level=ERROR)
        msg = ("Unexpected error occurred while processing requests: %s" %
               (reqs))
        log(msg, level=ERROR)
        return {'exit-code': 1, 'stderr': msg}

    msg = ("Missing or invalid api version (%s)" % (version))
    resp = {'exit-code': 1, 'stderr': msg}
    if request_id:
        resp['request-id'] = request_id

    return resp


def process_requests_v1(reqs):
    """Process v1 requests.

    Takes a list of requests (dicts) and processes each one. If an error is
    found, processing stops and the client is notified in the response.

    Returns a response dict containing the exit code (non-zero if any
    operation failed along with an explanation).
    """
    log("Processing %s ceph broker requests" % (len(reqs)), level=INFO)
    for req in reqs:
        op = req.get('op')
        log("Processing op='%s'" % (op), level=DEBUG)
        # Use admin client since we do not have other client key locations
        # setup to use them for these operations.
        svc = 'admin'
        if op == "create-pool":
            params = {'pool': req.get('name'),
                      'replicas': req.get('replicas')}
            if not all(params.iteritems()):
                msg = ("Missing parameter(s): %s" %
                       (' '.join([k for k in params.iterkeys()
                                  if not params[k]])))
                log(msg, level=ERROR)
                return {'exit-code': 1, 'stderr': msg}

            # Mandatory params
            pool = params['pool']
            replicas = params['replicas']

            # Optional params
            pg_num = req.get('pg_num')
            if pg_num:
                # Ensure string
                pg_num = str(pg_num)

            if not pool_exists(service=svc, name=pool):
                log("Creating pool '%s' (replicas=%s)" % (pool, replicas),
                    level=INFO)
                create_pool(service=svc, name=pool, replicas=replicas,
                            pg_num=pg_num)
            else:
                log("Pool '%s' already exists - skipping create" % (pool),
                    level=DEBUG)
        else:
            msg = "Unknown operation '%s'" % (op)
            log(msg, level=ERROR)
            return {'exit-code': 1, 'stderr': msg}

    return {'exit-code': 0}
