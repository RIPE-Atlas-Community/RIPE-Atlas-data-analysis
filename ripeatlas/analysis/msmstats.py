#!/usr/bin/env python

# Class defitions for generic Atlas measurement statistics
# These are base classes which group functionality common to all
# measurement types (ping, traceroute, ...)

# statistics are collected at three levels:
#
# first the raw per probe, per target IP data
# second the aggregate over all probes for each target IP
# finally overall statistics for the measurement

from collections import defaultdict
import json
import time
import sys

from utils import dnsnamelookup


class measurementStats:
    """
    generic summary data on results from one msm_id 
    """
    def __init__(self, msm_id,type, dst_name, max_dest):
	self.msm_id = msm_id
	self.type = type
	self.destinationStats = {}
	self.destinationIPs = defaultdict(int)
	self.probes = defaultdict(int)
	self.aggregateDestinations = 0
        self.maxDestinations = max_dest
	self.destinationName = dst_name
	self.samples = 0

    def addData(self, probe_id, dst_addr, data):
        """
        Add data from one sample of the measurement
        Statistics are grouped by destination IP upto a maximum of maxDestinations
        When the measurement involves more destinations, statistics are aggregated
        """
        self.samples += 1
        self.probes[probe_id] += 1
        self.destinationIPs[dst_addr] += 1

        if self.aggregateDestinations:
            dst_addr = "All IPs combined"
        else:
            if not dst_addr in self.destinationStats:
                # do we want to add another destination specific report?
                if len(self.destinationStats.keys()) < self.maxDestinations:
                    # yes we do
                    self.destinationStats[dst_addr] = measurementDestStats(self.msm_id,dst_addr)

                else:
                    # no, there are too many destinations for this msm_id
                    # aggregate the lot
                    self.aggregateDestinations = 1
                    dst_addr = "All IPs combined"
                    self.aggregateDestStats(dst_addr)

        self.destinationStats[dst_addr].addData(probe_id,data)



    def  aggregateDestStats(self, aggregate_dst):
        """
        We have too many different destination IPs to report on seperately
        Aggregate per destination stats collected thusfar into new aggregate stats object
        All new data will be added there.
        """
        aggrStats = measurementDestStats(self.msm_id, aggregate_dst)
        for dest in self.destinationStats.keys():
            aggrStats.addDestinationStats(self.destinationStats[dest])
            del self.destinationStats[dest]
            
        self.destinationStats[aggregate_dst] = aggrStats

    def probecount(self):
	return(len(self.probes.keys()))

    def getDestinations(self):
	return(self.dst_addrs.keys())

    def report(self,detail):
	print "Report for measurement %7d" % self.msm_id
	print "------------------------------"
	print
	print "Measurement type: %s" % self.type
	if self.destinationName:
	    if not self.destinationName in self.destinationStats:
	        # don't print if name is an IP address
	        print "Destination hostname: %s" % self.destinationName

	numdest = len(self.destinationIPs.keys())
        print "Number of destination IP addresses: ", numdest

	numreports = len(self.destinationStats.keys())
	if (numdest > 1):
	    print "Total samples:                      ", self.samples
	    # more stuff aggregated over all destination IPs

	for addr in self.destinationStats.keys():
	    self.destinationStats[addr].report(detail)
		
	return

class measurementDestStats:
    'summary of ping results from one measurement to a single IP'
    def __init__(self, msm_id, dst_addr):
	self.msm_id = msm_id
	self.dst_addr = dst_addr
	self.probeReport = {}
	self.aggregationDone = 0

	self.samples = 0

	self.starttime = 9999999999
	self.endtime = 0


    def addData(self, probe_id, data):
	if not probe_id in self.probeReport:
	     self.probeReport[probe_id] = probeResults(self.msm_id,self.dst_addr,probe_id)

	self.probeReport[probe_id].addData(data)
	self.aggregationDone = 0

	
    def addDestinationStats(self, source):
        """
        add data from another destinationStats object to present one
        primary use case is creating aggregate stats over all
        destinations of the measurement
        """

        for probe_id in source.probeReport:
            if not probe_id in self.probeReport:
                self.probeReport[probe_id] = probeResults(self.msm_id,self.dst_addr,probe_id)
            self.probeReport[probe_id].addProbeResults(source.probeReport[probe_id])
        if source.aggregationDone:
            self.aggregateProbeData()



    def aggregateProbeData(self):
	"""
	compile aggregate statistics from the per probe results
	"""

	for probe_id in self.probeReport.keys():
	    counters = self.probeReport[probe_id].getCounts()
	    self.samples += counters['samples']

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

	try:
	    host = dnsnamelookup(self.dst_addr)
	except:
	    host = None
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


        print "Number of samples:", self.samples


	print


	return

class probeResults:
    """
    collect generic data from one probe to one destination'
    """
    def __init__(self, msm_id, dst_addr, probe_id):
    	self.probe_id = probe_id
	self.msm_id = msm_id
	self.dst_addr = dst_addr
        self.samples =0
	self.starttime = 9999999999
	self.endtime = 0

    def getCounts(self):
	counters = {}
	counters['samples'] = self.samples
	return(counters)


    def addData (self, data):
        """
        Process one record of an Atlas measurement 
        """

	self.samples += 1
	self.updateStartEnd(data['timestamp'])


    def addProbeResults(self, source):
        """
        Add data from another probeResults object to present stats
        main use case is collecting aggregate stats, not specific to one target IP
        """

        self.samples += source.samples

        self.updateStartEnd(source.starttime)
        self.updateStartEnd(source.endtime)



    def updateStartEnd(self,timestamp):
	if (timestamp < self.starttime):
	    self.starttime = timestamp
	if  (timestamp > self.endtime):
	    self.endtime = timestamp


