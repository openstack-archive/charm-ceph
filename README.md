# Overview

```NOTE: this charm has been deprecated and will not recieve updates past February 2018.  Please refer to the 'Migration' section for how to upgrade existing deployments of this charm.```

Ceph is a distributed storage and network file system designed to provide
excellent performance, reliability, and scalability.

This charm deploys a Ceph cluster.

# Migration

In order to continue to recieve updates to newer Ceph versions, and for general
improvements and features in the charms to deploy Ceph, users of the ceph charm
should migrate existing sevices to using ceph-mon and ceph-osd.

This example migration assumes that the ceph charm is deployed to machines 0, 1 and
2 with the ceph-osd charm deployed to other machines within the model.

## Deploy ceph-mon

First deploy the ceph-mon charm; if the existing ceph charm is deployed to machines
0, 1 and 2, you can place the ceph-mon units in LXD containers on these machines:

    juju deploy --to lxd:0 ceph-mon
    juju config ceph-mon no-bootstrap=True
    juju add-unit --to lxd:1 ceph-mon
    juju add-unit --to lxd:2 ceph-mon

These units will install ceph, but will not bootstrap into a running monitor cluster.

## Bootstrap ceph-mon from ceph

Next, we'll use the existing ceph application to bootstrap to new ceph-mon units:

    juju add-relation ceph ceph-mon

Once this process has completed, you should have a Ceph MON cluster of 6 units;
this can be verified on any of the ceph or ceph-mon units:

    sudo ceph -s

## Deploy ceph-osd to ceph units

In order to retain any running Ceph OSD processes on the ceph units, the ceph-osd
charm must be deployed to the existing machines running the ceph units:

    juju config ceph-osd osd-reformat=False
    juju add-unit --to 0 ceph-osd
    juju add-unit --to 1 ceph-osd
    juju add-unit --to 2 ceph-osd

The charm installation and configuration will not impact any existing running
Ceph OSD's.

## Relate ceph-mon to all ceph clients

The new ceph-mon units now need to be related to all applications using the Ceph
cluster:

    juju add-relation ceph-mon ceph-osd

and depending on your deployment:

    juju add-relation ceph-mon cinder-ceph
    juju add-relation ceph-mon glance
    juju add-relation ceph-mon nova-compute
    juju add-relation ceph-mon ceph-radosgw
    juju add-relation ceph-mon gnocchi

once hook execution completes across all units, each client should be configured
with 6 MON addresses.

## Remove the ceph application

Its now safe to remove the ceph application from your deployment:

    juju remove-application ceph

As each unit of the ceph application is destroyed, its stop hook will remove the
MON process from the Ceph cluster monmap and disable Ceph MON and MGR processes
running on the machine; any Ceph OSD processes remain untouched and are now
owned by the ceph-osd units deployed alongside ceph.

# Usage

The ceph charm has two pieces of mandatory configuration for which no defaults
are provided. You _must_ set these configuration options before deployment or the charm will not work:

    fsid:
        uuid specific to a ceph cluster used to ensure that different
        clusters don't get mixed up - use `uuid` to generate one.

    monitor-secret:
        a ceph generated key used by the daemons that manage to cluster
        to control security.  You can use the ceph-authtool command to
        generate one:

            ceph-authtool /dev/stdout --name=mon. --gen-key

These two pieces of configuration must NOT be changed post bootstrap; attempting
to do this will cause a reconfiguration error and new service units will not join
the existing ceph cluster.

The charm also supports the specification of storage devices to be used in the
ceph cluster.

    osd-devices:
        A list of devices that the charm will attempt to detect, initialise and
        activate as ceph storage.

        This can be a superset of the actual storage devices presented to each
        service unit and can be changed post ceph bootstrap using `juju set`.

        The full path of each device must be provided, e.g. /dev/vdb.

        For Ceph >= 0.56.6 (Raring or the Grizzly Cloud Archive) use of
        directories instead of devices is also supported.

At a minimum you must provide a juju config file during initial deployment
with the fsid and monitor-secret options (contents of cepy.yaml below):

    ceph:
        fsid: ecbb8960-0e21-11e2-b495-83a88f44db01
        monitor-secret: AQD1P2xQiKglDhAA4NGUF5j38Mhq56qwz+45wg==
        osd-devices: /dev/vdb /dev/vdc /dev/vdd /dev/vde

Specifying the osd-devices to use is also a good idea.

Boot things up by using:

    juju deploy -n 3 --config ceph.yaml ceph

By default the ceph cluster will not bootstrap until 3 service units have been
deployed and started; this is to ensure that a quorum is achieved prior to adding
storage devices.

## Actions

This charm supports pausing and resuming ceph's health functions on a cluster, for example when doing maintenance on a machine. to pause or resume, call:

`juju action do --unit ceph/0 pause-health` or `juju action do --unit ceph/0 resume-health`

## Scale Out Usage

You can use the Ceph OSD and Ceph Radosgw charms:

- [Ceph OSD](https://jujucharms.com/ceph-osd)
- [Ceph Rados Gateway](https://jujucharms.com/ceph-radosgw)

## Network Space support

This charm supports the use of Juju Network Spaces, allowing the charm to be bound to network space configurations managed directly by Juju.  This is only supported with Juju 2.0 and above.

Network traffic can be bound to specific network spaces using the public (front-side) and cluster (back-side) bindings:

    juju deploy ceph --bind "public=data-space cluster=cluster-space"

alternatively these can also be provided as part of a Juju native bundle configuration:

    ceph:
      charm: cs:xenial/ceph
      num_units: 1
      bindings:
        public: data-space
        cluster: cluster-space

Please refer to the [Ceph Network Reference](http://docs.ceph.com/docs/master/rados/configuration/network-config-ref) for details on how using these options effects network traffic within a Ceph deployment.

**NOTE:** Spaces must be configured in the underlying provider prior to attempting to use them.

**NOTE**: Existing deployments using ceph-*-network configuration options will continue to function; these options are preferred over any network space binding provided if set.

# Contact Information

## Authors

- Paul Collins <paul.collins@canonical.com>,
- James Page <james.page@ubuntu.com>

Report bugs on [Launchpad](http://bugs.launchpad.net/charms/+source/ceph/+filebug)

## Ceph

- [Ceph website](http://ceph.com)
- [Ceph mailing lists](http://ceph.com/resources/mailing-list-irc/)
- [Ceph bug tracker](http://tracker.ceph.com/projects/ceph)

# Technical Footnotes

This charm uses the new-style Ceph deployment as reverse-engineered from the
Chef cookbook at https://github.com/ceph/ceph-cookbooks, although we selected
a different strategy to form the monitor cluster. Since we don't know the
names *or* addresses of the machines in advance, we use the _relation-joined_
hook to wait for all three nodes to come up, and then write their addresses
to ceph.conf in the "mon host" parameter. After we initialize the monitor
cluster a quorum forms quickly, and OSD bringup proceeds.

The osds use so-called "OSD hotplugging". **ceph-disk prepare** is used to
create the filesystems with a special GPT partition type. *udev* is set up
to mount such filesystems and start the osd daemons as their storage becomes
visible to the system (or after `udevadm trigger`).

The Chef cookbook mentioned above performs some extra steps to generate an OSD
bootstrapping key and propagate it to the other nodes in the cluster. Since
all OSDs run on nodes that also run mon, we don't need this and did not
implement it.

See [the documentation](http://ceph.com/docs/master/dev/mon-bootstrap/) for more information on Ceph monitor cluster deployment strategies and pitfalls.
