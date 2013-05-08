#!/bin/sh

# wrapper for DNS reporting

# decode the answer buffer for each line, then feed the result to the
# real DNS reporting perl script

# NOTE: this relies on proper setting of PATH variable to find the 
# python/perl scripts to run

decode_abuf.py -do -dh | dnsReport.pl -d $1

