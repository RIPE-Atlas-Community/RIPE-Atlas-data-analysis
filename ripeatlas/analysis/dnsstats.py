#!/usr/bin/env python

# Class defitions for Atlas DNS statistics

# statistics are collected at three levels:
#
# first the raw per probe, per target IP data
# second the aggregate over all probes for each target IP
# finally overall statistics for the measurement

from collections import defaultdict

import json
import time
import sys
import re


from ripeatlas.analysis.msmstats import measurementStats, measurementDestStats, probeResults
from ripeatlas.analysis.utils import dnsnamelookup


class dnsStatistics(measurementStats):
    """
    top level statistics for DNS measurement
    the "measurementsStats" base class holds most of the methods
    here we only need to override the addData() method with
    one specific to DNS
    """

    def addData(self, probe_id, dst_addr, data):
        """
        Add data from one sample of the DNS measurement
        Statistics are grouped by seperate objects per destination IP upto a maximum
	of maxDestinations. When the measurement involves more destinations
	(target DNS servers), the statistics are aggregated.
        """

        self.samples += 1
        self.probes[probe_id] += 1
        self.destinationIPs[dst_addr] += 1

        if self.aggregateDestinations:
	    # don't split statistics per 'dst_addr', group all data under same 'host'
            dst_addr = "All IPs combined"
        else:
            if not dst_addr in self.destinationStats:
                # do we want to add another destination specific report?
                if len(self.destinationStats.keys()) < self.maxDestinations:
                    # yes we do
                    self.destinationStats[dst_addr] = dnsDestinationStats(self.msm_id,dst_addr)
                else:
                    # no, there are too many destinations for this msm_id
                    # aggregate what we have thusfar
                    shelf.aggregateDestinations = 1
                    dst_addr = "All IPs combined"
                    self.aggregateDestStats(dst_addr)

        self.destinationStats[dst_addr].addData(probe_id,data)


    def  aggregateDestStats(self, aggregate_dst):
        """
        We have too many different destination IPs to report on seperately
        Aggregate per destination stats collected thusfar into new aggregate stats object
        All new data will be added there.
        """
        aggrStats = dnsDestinationStats(self.msm_id, aggregate_dst)
        for dest in self.destinationStats.keys():
            aggrStats.addDestinationStats(self.destinationStats[dest])
            del self.destinationStats[dest]
            
        self.destinationStats[aggregate_dst] = aggrStats



class dnsDestinationStats:
    """
    summary of DNS  results from one measurement to a single destination
    (or aggregated for all destinations when there are too many to report
    on individually)
    """

    def __init__(self, msm_id, dst_addr):
	"""
	Constructor. Initialize various counters and dictionaries
	"""

	self.msm_id = msm_id
	self.dst_addr = dst_addr
	self.probeReport = {}
	self.samples = 0
	
	#
        # Add specific DNS related fields as appropriate
	#

	self.aggregationDone = 0

	self.starttime = 9999999999
	self.endtime = 0


    def addData(self, probe_id, data):
	"""
	Add data for a specific probe
	Most of this will happen in the "probeDNSResults" objects 
	Once a report is requested, the per probe results will be aggregated
	into per destination results
	"""

	if not probe_id in self.probeReport:
	     self.probeReport[probe_id] = probeDNSResults(self.msm_id,self.dst_addr,probe_id)

	self.probeReport[probe_id].addData(data)
	self.aggregationDone = 0


    def addDestinationStats(self, source):
        """
        add data from another destinationStats object to present one
        primary use case is creating aggregate stats over all
        destination IP addresses of the measurement
        """

        for probe_id in source.probeReport:
            if not probe_id in self.probeReport:
                self.probeReport[probe_id] = probeDNSResults(self.msm_id,self.dst_addr,probe_id)
            self.probeReport[probe_id].addProbeResults(source.probeReport[probe_id])
        if source.aggregationDone:
            self.aggregateProbeData()


	

    def aggregateProbeData(self):
	"""
	compile aggregate statistics from the per probe results
	this is a necessary step in preparation for reporting overall results
	"""

	for probe_id in self.probeReport.keys():
	    counters = self.probeReport[probe_id].getCounts()

	    self.samples += counters['samples']

	    # add more counters and other statistics as appropriate for DNS


            starttime = self.probeReport[probe_id].starttime
            endtime = self.probeReport[probe_id].endtime
            if (starttime < self.starttime):
                self.starttime = starttime
            if (endtime > self.endtime):
                self.endtime = endtime


	self.aggregationDone = 1

	
	
    def report(self,detail):
	"""
	Output a report on the collected statistics
	The 'detail' argument controls how much detail is provided
	(more detail, longer reports)
	"""

        if not self.aggregationDone:
	   # aggregate the per probe results before reporting
	   self.aggregateProbeData()

	host = dnsnamelookup(self.dst_addr)
	nprobes = len(self.probeReport.keys())
	if (detail==0):
	    if host:
		print "Destination:", self.dst_addr, " / " , host
	    else:
		print "Destination:", self.dst_addr
	else:
	    print "Destination:", self.dst_addr
	    if host:
		print "Reverse DNS:", host

	print "Timeinterval:" , time.strftime("%Y-%m-%dT%H:%MZ",time.gmtime(self.starttime)), " - ", time.strftime("%Y-%m-%dT%H:%MZ",time.gmtime(self.endtime))
	print "Number of samples:  " , self.samples
	print


	return


class probeDNSResults(probeResults):
    """
    collect DNS data from one probe to one destination 
    here is where the bulk of the work is done
    """

    def __init__(self, msm_id, dst_addr, probe_id):
	"""
	Constructor. Initialize various counters 
	"""

    	self.probe_id = probe_id
	self.msm_id = msm_id
	self.dst_addr = dst_addr
        self.samples =0
	self.starttime = 9999999999
	self.endtime = 0

	#
        # Add specific DNS related fields as appropriate
	#

    def getCounts(self):
	counters = {}
	counters['samples'] = self.samples
	return(counters)
    

    def addData(self,data):
	"""
	Process and add data from one single measurement result
	"""

	#print "probe: ",self.probe_id
	self.samples += 1
	self.updateStartEnd(data['timestamp'])

	# decode abuf

	# parse the complete json, extract parameters, per probe statistics
	# (RTTs, error/success, etc.)
	

        return


    def addProbeResults(self, source):
        """
        Add data from another DNSResults object to present stats
        main use case is collecting aggregate stats, not specific to one target IP
        """

        self.samples += source.samples

	#
        # Update the other DNS related fields with those from the source object
	#

        self.updateStartEnd(source.starttime)
        self.updateStartEnd(source.endtime)




