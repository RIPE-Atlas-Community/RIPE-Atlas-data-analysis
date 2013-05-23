#!/usr/bin/env python

# report.py - front end script to Atlas measurement reporting


from collections import defaultdict
import argparse
import fileinput
import simplejson as json
import sys
import os
import time
import subprocess

from ripeatlas.analysis.msmstats import measurementStats
from ripeatlas.analysis.pingstats import pingStatistics
from ripeatlas.analysis.tracestats import traceStatistics
from ripeatlas.analysis.dnsstats import dnsStatistics


def processRecord (line,results,args):
    """
    Process one record, one measurement result 
    Details vary per measurement type and are taken care of
    in the per class methods

    Note: for now the detailed DNS results are produced by external python/perl code
    we will integrate that into the python class structure in the next weeks
    """

    try:
	data = json.loads(line);
    except:
	print >>sys.stderr, "Error parsing JSON. line: %s" % line
	return

    probe_id = data.get('prb_id')
    msm_id = data.get('msm_id')
    type = data.get('type')
    fw = data.get('fw')

    if ((not probe_id) | (not msm_id) | (not type) | (not fw)):
	results['corrupt'] = results.get('corrupt',0) + 1
        return

    if (fw < 4000):
        # Silently discard measurements with outdated firmware; JSON formats differs too much.
        # This typically happens when old version 1 or 2 probes connect for the first time
	results['oldformat'] = results.get('oldformat',0) + 1
        return(0)

    dst_addr = data.get('dst_addr','unspecified')
    dst_name = data.get('dst_name')
    protocol = data.get('proto')
    
   
    msmresults = results.get(msm_id)
    if not msmresults:
	# initialize new object using appropriate class
	if (type == 'ping') & (protocol == 'ICMP'):
       	    msmresults = pingStatistics(msm_id,type,dst_name,args.maxdest)
	elif (type == 'traceroute'):
	    msmresults = traceStatistics(msm_id,type,dst_name,args.maxdest)
	elif (type == 'dns'):
	    msmresults = dnsStatistics(msm_id,type,dst_name,args.maxdest)

	    # temporary: also feed the line to seperate dns reporting script 
	    # (this is to be integrated into the general analysis & reporting framework)
	    if not 'dnsReport' in results:
		# open the pipeline for dns processing
		# Note: this relies on the relevant scripts being in the search PATH
		try:
		    script = "dnsReport.sh"
		    pipe = subprocess.Popen([script,"-d","%d" % args.detail], stdin=subprocess.PIPE)
		    results['dnsReport']=pipe
		except Exception:
		    (exc_type, exc_value, exc_traceback) = sys.exc_info()
		    print >>sys.stderr, "ERROR opening pipe for %s:" % script, exc_value
		    print >>sys.stderr
		    os._exit(1)

		    
	
	else:
	    msmresults = measurementStats(msm_id,type,dst_name,args.maxdest)
        results[msm_id] = msmresults
            
    msmresults.addData(probe_id, dst_addr, data)

    if (type == 'dns'):
	print >>results['dnsReport'].stdin, line
	
    return




####   MAIN program



parser = argparse.ArgumentParser(description='Produce report on Atlas measurements.')
parser.add_argument('-v','--verbosity', action="count",default=0)
parser.add_argument('-d','--detail', help='level of detail to report', type=int,default=1)
parser.add_argument('-m','--maxdest', help='max number of destination IPs to report on individually; when exceeded produce aggreate report  ', type=int,default=3)
parser.add_argument('filenames', metavar='file',  nargs='*',
                   help='input files [default: stdin]')
args = parser.parse_args()



results={}
totalLines = 0

# read the data
for line in fileinput.input(args.filenames):
    processRecord(line,results,args);
    totalLines += 1

# temporary, until DNS stats are integrated in our class libraries:
dnsReport = results.get('dnsReport')
if dnsReport:
   del results['dnsReport']

# report on incomplete/corrupt lines and results in too old data format
corrupted = results.get('corrupt')
if corrupted:
    print >>sys.stderr, "warning: %d lines out of %d with incomplete JSON data (probe_id,msm_id or fw missing)" % (corrupted, totalLines)
    del results['corrupt']

oldformat = results.get('oldformat')
if oldformat:
    print >>sys.stderr, "warning: %d lines out of %d using deprected data format (probe firmware < 4000)" % (oldformat, totalLines)
    del results['oldformat']


# output report for each measurement id found in input data
for msm_id in sorted(results.keys()):
	results[msm_id].report(args.detail)

if dnsReport:
    dnsReport.stdin.close()
    dnsReport.wait()

exit
