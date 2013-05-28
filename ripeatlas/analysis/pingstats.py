#!/usr/bin/env python

# Class defitions for Atlas Ping statistics

# statistics are collected at three levels:
#
# first the raw per probe, per target IP data
# second the aggregate over all probes for each target IP
# finally overall statistics for the measurement

from collections import defaultdict
import json
import time
import sys

from ripeatlas.analysis.msmstats import measurementStats, measurementDestStats, probeResults
from ripeatlas.analysis.utils import dnsnamelookup



class pingStatistics(measurementStats):
    """
    top level statistics for ping measurement
    the "measurementsStats" base class holds most of the methods
    here we only need to override the addData() method with
    one specific one for pings
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
	     	    self.destinationStats[dst_addr] = pingDestinationStats(self.msm_id,dst_addr)
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
	aggrStats = pingDestinationStats(self.msm_id, aggregate_dst)
	for dest in self.destinationStats.keys():
	    aggrStats.addDestinationStats(self.destinationStats[dest])
	    del self.destinationStats[dest]
	    
	self.destinationStats[aggregate_dst] = aggrStats



class pingDestinationStats:
    'summary of ping results from one measurement to a single IP'
    def __init__(self, msm_id, dst_addr):
	self.msm_id = msm_id
	self.dst_addr = dst_addr
	self.probeReport = {}
	self.aggregationDone = 0

	self.packets_sent = 0
    	self.packets_rcvd = 0
    	self.packets_dup = 0

	self.nodata = 0
	self.allerrors = 0
	self.errorMsgs = defaultdict(int)

	self.loss100 = 0
        self.loss80 = 0
        self.loss60 = 0
        self.loss40 = 0
        self.loss20 = 0
        self.loss5 = 0
	self.loss0 = 0
	self.lossless = 0
	self.minimumRtts = []
	self.medianRtts = []
	self.maximumRtts = []
	self.min = 0
	self.max = 0
	self.level975 = 0
	self.level025 = 0
	self.starttime = 9999999999
	self.endtime = 0


    def addData(self, probe_id, data):
	if not probe_id in self.probeReport:
	     self.probeReport[probe_id] = probePingResults(self.msm_id,self.dst_addr,probe_id)

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
	        self.probeReport[probe_id] = probePingResults(self.msm_id,self.dst_addr,probe_id)
            self.probeReport[probe_id].addProbeResults(source.probeReport[probe_id])
	if source.aggregationDone:
	    self.aggregateProbeData()



    def aggregateProbeData(self):
	"""
	compile aggregate statistics from the per probe results
	"""

	for probe_id in self.probeReport.keys():
	    counters = self.probeReport[probe_id].getCounts()
	    percentiles = self.probeReport[probe_id].rttPercentiles()
	    loss = self.probeReport[probe_id].lossRate()
	    errorrate = self.probeReport[probe_id].errorRate()

	    self.packets_sent += counters['sent']
    	    self.packets_rcvd += counters['received']
    	    self.packets_dup += counters['duplicate']

	    for msg in self.probeReport[probe_id].errors:
		self.errorMsgs[msg] += 1
	    if (counters['sent'] == 0):
		if errorrate == 1:
	       	    self.allerrors += 1
		else:
	            self.nodata += 1
	    elif (counters['received'] == 0):
	       self.loss100 += 1
	    elif (counters['received'] == counters['sent']):
	       self.lossless += 1
	    elif (loss > 0.80):
	       self.loss80 += 1
	    elif (loss > 0.60):
	       self.loss60 += 1
	    elif (loss > 0.40):
	       self.loss40 += 1
	    elif (loss > 0.20):
	       self.loss20 += 1
	    elif (loss > 0.05):
	       self.loss5 += 1
	    elif (loss > 0.0):
	       self.loss0 += 1

	    if '0' in percentiles and '50' in percentiles and  '100' in percentiles:
	        self.minimumRtts += [percentiles.get('2.5')]
	        self.medianRtts += [percentiles.get('50')]
	        self.maximumRtts += [percentiles.get('97.5')]

            starttime = self.probeReport[probe_id].starttime
            endtime = self.probeReport[probe_id].endtime
            if (starttime < self.starttime):
                self.starttime = starttime
            if (endtime > self.endtime):
                self.endtime = endtime


	self.minimumRtts.sort()
	self.medianRtts.sort()
	self.maximumRtts.sort()
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

	# Look for reverse DNS (if any)
	host = dnsnamelookup(self.dst_addr)
	if (detail==0):
	    if host:
		print "Destination:", self.dst_addr, " / " , host
	    else:
		print "Destination:", self.dst_addr
	else:
	    print "Destination:", self.dst_addr
	    if host:
		print "Reverse DNS:", host


	nprobes = len(self.probeReport.keys())

	if (self.packets_sent>0):
    	    lost = 100 * (self.packets_sent - self.packets_rcvd)/float(self.packets_sent)
	    lost = "%.2f%%" % lost
	else:
    	    lost = "NA"
	    
	if (detail==0):
	    #minimal view; report median of the medians
	    if len(self.medianRtts) > 0:
	        numprobes = len(self.medianRtts) 
	        level500 = int(numprobes * 0.5)
                median = self.medianRtts[level500]
		median = "%.2fms" % median
	    else:
		median = "NA"
	    print "sent/received/loss/median %d/%d/%s/%s" % (self.packets_sent,self.packets_rcvd,lost,median)

	else:
	    print "Timeinterval:" , time.strftime("%Y-%m-%dT%H:%MZ",time.gmtime(self.starttime)), " - ", time.strftime("%Y-%m-%dT%H:%MZ",time.gmtime(self.endtime))
	    print "Packets sent:", self.packets_sent
	    print "Packets received:", self.packets_rcvd

	    print "Overall loss rate: %s" % lost
	    print
	    print "Total probes measuring: %6d" % nprobes
	    print "Probes with 100%% errors:%6d" % self.allerrors
	    if len(self.errorMsgs)>0:
	        print 'Total errors on probes: %6d' % sum(self.errorMsgs.values())
	        print 'Most common error:"%s (%dx)"' % sorted(self.errorMsgs.items(),key=lambda x: x[1], reverse=True)[0]
		
	    if (nprobes > 1):
	        print
	        print "Probes with no packets lost:   %6d" % self.lossless
	        print "Probes with 0%%-5%% loss:        %6d" % self.loss0
	        print "Probes with 5%%-20%% loss:       %6d" % self.loss5
	        print "Probes with 20%%-40%% loss:      %6d" % self.loss20
	        print "Probes with 40%%-60%% loss:      %6d" % self.loss40
	        print "Probes with 60%%-80%% loss:      %6d" % self.loss60
	        print "Probes with 80%%-100%% loss:     %6d" % self.loss80
	        print "Probes with 100%% loss:         %6d" % self.loss100
	        print "Probes not sending any packets:%6d" % self.nodata

	    print 
	    if len(self.medianRtts) > 0:
	        numprobes = len(self.medianRtts) 
	        level025 = int(numprobes * 0.025)
	        level250 = int(numprobes * 0.25)
	        level500 = int(numprobes * 0.5)
	        level750 = int(numprobes * 0.75)
	        level975 = int(numprobes * 0.975)
	        print "RTT distributions:"
	        print "-----------------\n"

	        print '2.5 percentile ("Minimum")'
	        print "lowest 2.5 percentile RTT in all probes:%8.2fms"  % self.minimumRtts[0]
	        print "2.5%% of probes had 2.5 percentile    <= %8.2fms" % self.minimumRtts[level025]
	        print "25%% of probes had 2.5 percentile     <= %8.2fms" % (self.minimumRtts[level250])
	        print "50%% of probes had 2.5 percentile     <= %8.2fms" % (self.minimumRtts[level500])
	        print "75%% of probes had 2.5 percentile     <= %8.2fms" % (self.minimumRtts[level750])
	        print "97.5%% of probes had 2.5 percentile   <= %8.2fms" % (self.minimumRtts[level975])
	        print "highest 2.5 percentile in all probes    %8.2fms"  % (self.minimumRtts[numprobes-1])
	        print
	        print "Median"
	        print "lowest median RTT in all probes     %9.2fms"  % self.medianRtts[0]
	        print "2.5%% of probes had median RTT    <= %9.2fms" % self.medianRtts[level025]
	        print "25%% of probes had median RTT     <= %9.2fms" % (self.medianRtts[level250])
	        print "50%% of probes had median RTT     <= %9.2fms" % (self.medianRtts[level500])
	        print "75%% of probes had median RTT     <= %9.2fms" % (self.medianRtts[level750])
	        print "97.5%% of probes had median RTT   <= %9.2fms" % (self.medianRtts[level975])
	        print "highest median RTT in all probes    %9.2fms"  % (self.medianRtts[numprobes-1])
	        print
	        print '97.5 percentile ("Maximum")'
	        print "lowest 97.5 percentile RTT in all probes:%8.2fms"  % self.maximumRtts[0]
	        print "2.5%% of probes had 97.5 percentile    <= %8.2fms" % self.maximumRtts[level025]
	        print "25%% of probes had 97.5 percentile     <= %8.2fms" % (self.maximumRtts[level250])
	        print "50%% of probes had 97.5 percentile     <= %8.2fms" % (self.maximumRtts[level500])
	        print "75%% of probes had 97.5 percentile     <= %8.2fms" % (self.maximumRtts[level750])
	        print "97.5%% of probes had 97.5 percentile   <= %8.2fms" % (self.maximumRtts[level975])
	        print "highest 97.5 percentile in all probes    %8.2fms"  % (self.maximumRtts[numprobes-1])
        print
	print


	return

class probePingResults(probeResults):
    """
    collect ping data from one probe to one destination'
    """
    def __init__(self, msm_id, dst_addr, probe_id):
    	self.probe_id = probe_id
	self.msm_id = msm_id
	self.dst_addr = dst_addr
        self.samples =0
    	self.packets_sent = 0
    	self.packets_rcvd = 0
    	self.packets_dup = 0
	self.errors = defaultdict(int)
    	self.rtts = []
	self.rtts_sorted = 0
	self.starttime = 9999999999
	self.endtime = 0

    def getCounts(self):
	counters = {}
	counters['sent'] = self.packets_sent
	counters['received'] = self.packets_rcvd
	counters['duplicate'] = self.packets_dup
	return(counters)

    def lossRate(self):
	if (self.packets_sent>0):
	    loss = (self.packets_sent-self.packets_rcvd) / float(self.packets_sent)
	else:
	    loss = 99999999999
	return(loss)

    def errorRate(self):
	total = len(self.errors) + len(self.rtts)
        if total>0:
	    errorrate = len(self.errors) / total
	else:
	    errorrate = 99999999999
	return(errorrate)

    def addData (self, data):
        """
        Process one record of an Atlas ping measurement, update statistics
	See https://atlas.ripe.net/doc/data_struct#v4460_ping for details on 
	the possible fields found in 'data' dictionary
        """

	self.samples += 1
	self.packets_sent += data['sent']
	self.packets_dup += data['dup']
	self.packets_rcvd += data['rcvd']

	self.updateStartEnd(data['timestamp'])

	for item in data['result']:
	    if 'error' in item:
		self.errors[item['error']] += 1
	    if 'rtt' in item and not 'dup' in item:
		# rtt for duplicates is not representative, often too late
		self.rtts += [item['rtt']]
		
	return


    def addProbeResults(self, source):
	"""
	Add data from another pingResults object to present stats
	main use case is collecting aggregate stats, not specific to one target IP
	"""

	self.samples += source.samples
	self.packets_sent += source.packets_sent
	self.packets_dup += source.packets_dup
	self.packets_rcvd += source.packets_rcvd

	self.updateStartEnd(source.starttime)
	self.updateStartEnd(source.endtime)

    	self.rtts += source.rtts 
	if self.rtts_sorted:
	    self.rtts.sort()



    def rttPercentiles(self):

	 percentiles={}
	 if (len(self.rtts) > 0):
	    if not self.rtts_sorted:
		self.rtts.sort()
	    	self.rtts_sorted = 1

	    index025 = int(len(self.rtts)*0.025)
	    index500 = int(len(self.rtts)*0.5)
	    index975 = int(len(self.rtts)*0.975)

	    percentiles['100'] = self.rtts[len(self.rtts)-1]
	    percentiles['97.5'] = self.rtts[index975]
	    percentiles['50'] = self.rtts[index500]
	    percentiles['2.5'] = self.rtts[index025]
	    percentiles['0'] = self.rtts[0]

   	 return(percentiles)
