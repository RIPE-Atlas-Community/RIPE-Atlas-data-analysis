import dns.reversename
import dns.resolver
import sys

def dnsnamelookup(ipaddr):
    try:
        n = dns.reversename.from_address(ipaddr)
        try:
	    answers = dns.resolver.query(n, 'PTR')
    	except Exception:
	    #print >>sys.stderr, "%s: dns query failed" % n
	    return(None)
    
        host = ""
        for rdata in answers:
	    if (host):
	        host += " "
	    host += rdata.to_text()
    except Exception:
	#print >>sys.stderr, "%s: dns reversename failed" % ipaddr
	return(None)

    return(host)
