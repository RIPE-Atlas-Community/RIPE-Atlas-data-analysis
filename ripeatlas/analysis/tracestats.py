#!/usr/bin/env python

# Class defitions for Atlas Traceroute statistics

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


class traceStatistics(measurementStats):
    """
    top level statistics for traceroute  measurement
    the "measurementsStats" base class holds most of the methods
    here we only need to override the addData() method with
    one specific to traceroutes
    """

    def addData(self, probe_id, dst_addr, data):
        """
        Add data from one sample of the measurement
        Statistics are grouuped by destination IP upto a maximum of maxDestinations
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
                    self.destinationStats[dst_addr] = traceDestinationStats(self.msm_id,dst_addr)
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
        aggrStats = traceDestinationStats(self.msm_id, aggregate_dst)
        for dest in self.destinationStats.keys():
            aggrStats.addDestinationStats(self.destinationStats[dest])
            del self.destinationStats[dest]
            
        self.destinationStats[aggregate_dst] = aggrStats



class traceDestinationStats:
    'summary of traceroute results from one measurement to a single IP'
    def __init__(self, msm_id, dst_addr):
	self.msm_id = msm_id
	self.dst_addr = dst_addr
	self.probeReport = {}
	self.samples = 0
	self.completetraces = 0
	self.totalhopcount = 0
	self.destnotreached = 0
	self.ipvectors = 0

	self.aggregationDone = 0

	self.starttime = 9999999999
	self.endtime = 0


    def addData(self, probe_id, data):
	if not probe_id in self.probeReport:
	     self.probeReport[probe_id] = probeTraceResults(self.msm_id,self.dst_addr,probe_id)

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
                self.probeReport[probe_id] = probeTraceResults(self.msm_id,self.dst_addr,probe_id)
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
	    self.totalhopcount += counters['totalhopcount']
	    self.completetraces += counters['completetraces']
	    self.destnotreached += counters['destnotreached']
	    self.ipvectors += counters['ipvectors']


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
	print "Number of traces:", self.samples
	print "Number of unique routing vectors:", self.ipvectors
	print "Traces reaching target IP address: ",self.completetraces
	if (self.completetraces > 0):
	    print "Average hop count: %.2f" % (float(self.totalhopcount)/self.completetraces)
	else:
	    print "Average hop count:", "-"
	print "Traces not ending at target IP",self.destnotreached
	print 
	print


	return


class probeTraceResults(probeResults):
    """
    collect traceroute data from one probe to one destination
    """
    def __init__(self, msm_id, dst_addr, probe_id):
    	self.probe_id = probe_id
	self.msm_id = msm_id
	self.dst_addr = dst_addr
        self.samples =0
	self.completetraces = 0
	self.totalhopcount = 0
	self.destnotreached = 0
	self.ipvectors = defaultdict(int)
	self.starttime = 9999999999
	self.endtime = 0

    def getCounts(self):
	counters = {}
	counters['samples'] = self.samples
	counters['destnotreached'] = self.destnotreached
	counters['totalhopcount'] = self.totalhopcount
	counters['completetraces'] = self.completetraces
	counters['ipvectors'] = len(self.ipvectors.keys())
	return(counters)
    

    def addData(self,data):
	"""
	Process and add data from one single measurement result
	"""

	#print "probe: ",self.probe_id
	self.samples += 1
	self.updateStartEnd(data['timestamp'])

	hopdata = data.get('result')
	if (hopdata):
	    vector = parseTraceData(hopdata)
	    self.ipvectors[vector] += 1
	    lasthop = hopdata[len(hopdata)-1]
	    lasthopNum = lasthop.get('hop',0)

	    # did it reach destination?
	    match = 0
	    lasthopResults = lasthop.get('result')
	    if (lasthopResults):
		# no errors on last hop
	    	for res in lasthopResults:
		    if (res.get('from') == data['dst_addr']):
		        match = 1
	
	    if (match):
		self.completetraces +=1
		self.totalhopcount += lasthopNum
	    else:
		self.destnotreached +=1
	

        return


    def addProbeResults(self, source):
        """
        Add data from another traceResults object to present stats
        main use case is collecting aggregate stats, not specific to one target IP
        """

	self.completetraces += source.completetraces 
	self.totalhopcount += source.totalhopcount 
	self.destnotreached += source.destnotreached
	for vector in source.ipvectors:
	    self.ipvectors[vector] += 1

        self.samples += source.samples

        self.updateStartEnd(source.starttime)
        self.updateStartEnd(source.endtime)




def parseTraceData(data):

    """
    parse traceroute result, extract routing vector as a string
    """

    """
    Example traceroute record:

    {"endtime":1364774809,"result":[{"result":[{"x":"*"},{"x":"*"},{"x":"*"}],"hop":1},{"result":[{"late":3,"from":"192.168.1.1","ttl":64,"size":96},{"x":"*"},{"x":"*"},{"late":4,"from":"192.168.1.1","ttl":64,"size":96},{"x":"*"}],"hop":2},{"result":[{"x":"*"},{"x":"*"},{"late":6,"from":"192.168.1.1","ttl":64,"size":96},{"from":"86.110.159.250","rtt":208.642,"ttl":126,"size":56}],"hop":3},{"result":[{"from":"86.110.159.250","rtt":13.668,"ttl":126,"size":56},{"from":"86.110.159.250","rtt":1.43,"ttl":126,"size":56},{"ittl":0,"from":"10.174.200.42","rtt":2.725,"ttl":253,"size":56}],"hop":4},{"result":[{"ittl":0,"from":"10.174.200.42","rtt":17.853,"ttl":253,"size":56},{"ittl":0,"from":"10.174.200.42","rtt":3.063,"ttl":253,"size":56},{"dup":true,"from":"10.174.200.98","rtt":7.725,"ttl":252,"size":56},{"from":"10.174.200.98","rtt":15.661,"ttl":252,"size":56}],"hop":5},{"result":[{"from":"10.174.200.98","rtt":3.746,"ttl":252,"size":56},{"from":"217.29.66.125","rtt":13.618,"ttl":60,"size":56},{"from":"10.174.200.42","rtt":2.505,"ttl":253,"size":56},{"dup":true,"from":"10.174.200.42","rtt":4.791,"ttl":253,"size":56},{"dup":true,"from":"10.174.200.42","rtt":6.491,"ttl":253,"size":56},{"dup":true,"from":"217.29.66.125","rtt":8.051,"ttl":60,"size":56}],"hop":6},{"result":[{"from":"217.29.66.125","rtt":11.235,"ttl":60,"size":56},{"from":"184.105.222.129","rtt":23.14,"ttl":59,"size":56},{"from":"184.105.222.129","rtt":4.102,"ttl":59,"size":56}],"hop":7},{"result":[{"from":"184.105.222.129","rtt":17.619,"ttl":59,"size":56},{"from":"184.105.222.49","rtt":31.51,"ttl":58,"size":56},{"from":"184.105.222.49","rtt":6.728,"ttl":58,"size":56}],"hop":8},{"result":[{"from":"184.105.222.49","rtt":35.666,"ttl":58,"size":56},{"from":"184.105.213.93","rtt":80.129,"ttl":57,"size":56},{"from":"184.105.213.93","rtt":34.044,"ttl":57,"size":56}],"hop":9},{"result":[{"from":"184.105.213.93","rtt":47.287,"ttl":57,"size":56},{"from":"184.105.213.110","rtt":42.499,"ttl":56,"size":56},{"from":"184.105.213.110","rtt":98.492,"ttl":56,"size":56}],"hop":10},{"result":[{"from":"184.105.213.110","rtt":24.383,"ttl":56,"size":56},{"from":"216.66.0.50","rtt":179.865,"ttl":239,"size":56},{"from":"216.66.0.50","rtt":19.918,"ttl":239,"size":56}],"hop":11},{"result":[{"from":"216.66.0.50","rtt":178.447,"ttl":239,"size":56},{"from":"192.5.5.241","rtt":28.527,"ttl":48,"size":56},{"from":"192.5.5.241","rtt":154.97,"ttl":48,"size":56}],"hop":12},{"result":[{"from":"192.5.5.241","rtt":32.911,"ttl":48,"size":56},{"ittl":2,"from":"192.5.5.241","rtt":5633.67,"ttl":48,"size":56},{"dup":true,"ittl":2,"rtt":5637.374,"from":"192.5.5.241","ttl":48,"size":56},{"ittl":2,"from":"192.5.5.241","rtt":209.874,"ttl":48,"size":56}],"hop":13}],"dst_addr":"192.5.5.241","paris_id":1,"src_addr":"192.168.1.31","fw":4500,"prb_id":853,"from":"86.110.147.43","type":"traceroute","proto":"UDP","size":40,"dst_name":"192.5.5.241","timestamp":1364774756,"msm_id":5004,"msm_name":"Traceroute","af":4}
    """

    vector=''
    for hop in data:
	hopnum = hop.get('hop')
	#print "\n",hopnum

	error = hop.get('error')
	if error:
	    vector += error
	
	lastip = ''
	ipstring = ''
	hopresult = hop.get('result')
	if hopresult:
	    for packet in hopresult:
	        # collect the unique IP numbers or errors seen at this hop
		
		#print packet
		if packet.get('x') == '*':
  		    regex = re.compile("[0-9a-fA-F]+[:\.]")
    		    match = regex.match(ipstring)
		    if not match:
			# timedout response ignored when we already have an IP at this hop
			ipstring += "* "
		elif ('from' in packet) and (not 'late' in packet) and (not 'ittl' in packet):
                    # for now only process 'normal' responses
		    # 'late' packets are from previous hops, did not make it back in time
                    # packets containing 'ittl' are from future hops; the router at this 
		    # hop forwarded the packet even though it had a ttl equal to 1
		    response = 1
		    ip = packet['from']
		    errorflag = packet.get('err')
		    if errorflag:
			ip += " !" + str(errorflag)
		    if ip != lastip:
			lastip = ip
			if (ipstring == '* ') | (ipstring == '* * '):
			    # ignore previous timeouts at this hop
			    ipstring = ''
			ipstring += ip + ' '
		elif 'error' in packet:
		    ipstring += '"' + packet['error'] + '"'
	    if ipstring == '':
		# neither errors nor valid responses at this hop
		# make it '* * *' as we do need to have something
		ipstring = '* * *'

	    vector += ipstring + '\n'


    #print vector
    return(vector)



