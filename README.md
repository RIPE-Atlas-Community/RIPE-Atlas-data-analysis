RIPE-Atlas-data-analysis
========================

Overview
========
This package contains several components, notably:

    * atlasreport.py - the entry point for reporting statistics from RIPE Atlas data 
    * decodeabuf.py - a tool to decode the buffers returned in DNS queries
    * dnsReport.pl - a perl script which reports on DNS measurement results
    * dnsReport.sh - a shell script combining the two steps above, called by atlasreport.py 
    * a supporting Python class library where the real work is done

Licence
=======
This package is distributed under the terms of the LGPL v3 or later:

    https://raw.github.com/RIPE-Atlas-Community/RIPE-Atlas-data-analysis/master/LICENCE

Installation
============
The source code can be downloaded as a zip file rom https://github.com/RIPE-Atlas-Community/RIPE-Atlas-data-analysis/archive/master.zip 

You can install the package system wide by running the following command in 
the unpacked source directory::

    $ python setup.py install

or to install for a single user::

    $ python setup.py install --user; export PATH=$PATH:~/.local/bin

You can always upgrade to the latest release with this command::

    $ easy_install -U https://github.com/RIPE-Atlas-Community/RIPE-Atlas-data-analysis/tarball/master


Note that depending on the permissions you have on your system, the easy-install method may require set-up of a python virtual environment.

Dependencies
============
Dependencies in the python scripts are resolved at installation time by the setupu tools. The Perl script requires a JSON module to be installed. If it is not on your system, you can find it on CPAN, http://search.cpan.org/dist/JSON/


Disclaimer
==========
The programs are provided as is without any guarantees or warranty. Although
we have attempted to find and correct any bugs in the software, RIPE NCC is
not responsible for any damage or losses of any kind caused by the use or misuse
of the programs.

For more information, please send an email to the atlas@ripe.net mailbox.
