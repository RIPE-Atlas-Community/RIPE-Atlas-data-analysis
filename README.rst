ripestat-text
-------------

Licence
=======
This package is distributed under the terms of the LGPL v3 or later:

    https://raw.github.com/RIPE-NCC/ripestat-text/master/LICENCE

Installation
============

You can install the package system wide by running the following command in 
the source directory::

    $ python setup.py install

or to install for a single user::

    $ python setup.py install --user; export PATH=$PATH:~/.local/bin

You can always upgrade to the latest release with this command::

    $ easy_install -U https://github.com/RIPE-NCC/ripestat-text/tarball/master

Overview
========
This package contains several components, notably:

    * the main atlasreport.py tool reporting statistics from RIPE Atlas data 
    * the dnsReport.pl perl script to generate reports for DNS measurements
    * the decodeabuf.py tool to decode the buffers returned in DNS queries
    * the dnsReport.sh shell script which combines the two above in one pipeline
    * a supporting Python class library where the real work is done


