#!/usr/bin/env python
svn_id = "$Id:$"

# version 0.2
# 2013-04-05
# Bert Wijnen <bwijnen@ripe.net>
# - make it a standalone script that accepts on STDIN either:
#   * b64 encoded abuf(s). Will return (on STDOUT) a JSON structure
#   * RIPE Atlas Measurment Blob(s) in JSON format.
#     Will return i(on STDOUT) same JSON with DnsReply added
# - try to use (in the resulting JSON structuresi) the names as described in
#   draft-bortzmeyer-dns-json-01
# - use to_text routines from dns python package to convert class, type, codes to text
# - various options allow for control of results. like:
#   -doall (do all fields from abuf; i.e. a complete decoded DNS Reply
#   -dh (do just HEADER fields)
#   -doa( do options or EDNS0)
#   and more. See --help for details
#
# - you can also import the decode_abuf function that accepts as arguments
#   - the abuf (decoded b64)
#   - options dict, defaults is:
#     options{DO_Header=True, DO_Question=True, DO_Answer=True,
#             DO_Authority=True, DO_Additional=True, DO_Options=True}
#   - returns DnsReply JSON structure
#

# version 0.1
# 2013-02-25
# Philip Homburg <philip.homburg@ripe.net>
# - initial code, that decodes a hex encoded DNS answer buffer

import struct
import simplejson as json
import sys
import base64
import argparse
from   dns.opcode     import to_text as opcode_to_text
from   dns.rdataclass import to_text as class_to_text
from   dns.rcode      import to_text as rcode_to_text
from   dns.rdatatype  import to_text as type_to_text

def decode_abuf(buf, options={}): #, result):
        error         = []
        DO_HEADER     = True
        DO_QUESTION   = True
        DO_ANSWER     = True
        DO_AUTHORITY  = True
        DO_ADDITIONAL = True
        DO_OPTIONS    = True
        if options:
           if options.has_key('DO_Header') and not options['DO_Header']:
              DO_HEADER=options['DO_Header']
           if options.has_key('DO_Question') and not options['DO_Question']:
              DO_QUESTION=options['DO_Question']
           if options.has_key('DO_Answer') and not options['DO_Answer']:
              DO_ANSWER=options['DO_Answer']
           if options.has_key('DO_Authority') and not options['DO_Authority']:
              DO_AUTHORITY=options['DO_Authority']
           if options.has_key('DO_Additional') and not options['DO_Additional']:
              DO_ADDITIONAL=options['DO_Additional']
           if options.has_key('DO_Options') and not options['DO_Options']:
              DO_OPTIONS=options['DO_Options']

	dnsres= {}
	offset= 0
	offset, hdr = do_header(buf, offset)
        if DO_HEADER:
	   dnsres['HEADER']            = hdr
	for i in range(hdr['QDCOUNT']):
		offset, qry= do_query(buf, offset)
		if DO_QUESTION:
                        if i == 0:
 			   dnsres['QuestionSection']= [qry]
                        else:
			   dnsres['QuestionSection'].append(qry)
	for i in range(hdr['ANCOUNT']):
		offset, rr= do_rr(buf, offset)
		if DO_ANSWER:
                        if i == 0:
                           dnsres['AnswerSection']= [rr]
                        else:
			   dnsres['AnswerSection'].append(rr)
	for i in range(hdr['NSCOUNT']):
		offset, rr= do_rr(buf, offset)
		if DO_AUTHORITY:
                        if i == 0:
                           dnsres['AuthoritySection']= [rr]
                        else:
			   dnsres['AuthoritySection'].append(rr)
	for i in range(hdr['ARCOUNT']):
		res= do_rr(buf, offset)
		if res == None:
			e= ('additional', offset, ('do_rr failed, additional record %d' % i))
			error.append(e)
			dnsres['ERROR']= error
                        #result['decodedabufs_with_ERROR'] += 1
			return dnsres
		offset, rr= res
                if DO_OPTIONS:
		   if rr.has_key("EDNS0"):
			dnsres['EDNS0'] = rr['EDNS0']
                        continue
		if DO_ADDITIONAL:
                        if dnsres.has_key('AdditionalSection'):
			   dnsres['AdditionalSection'].append(rr)
                        else:
                           dnsres['AdditionalSection'] = [rr]
	if offset < len(buf):
		e= ('end', offset, 'trailing garbage, buf size = %d' % len(buf))
		error.append(e)
                #result['decodedabufs_with_ERROR'] += 1
		dnsres['ERROR']= error
		return dnsres
	return dnsres

def do_header(buf, offset):
	fmt= "!HHHHHH"
	reqlen= struct.calcsize(fmt)
	str= buf[offset:offset+reqlen]
	res= struct.unpack(fmt, str)
	#print res
	hdr={}
	hdr['ID']= res[0]
	
	QR=		0x8000
	Opcode_mask=	0x7800
	Opcode_shift=	11
	AA=		0x0400
	TC=		0x0200
	RD=		0x0100
	RA=		0x0080
	Z=		0x0040
	AD=		0x0020
	CD=		0x0010
	RCODE_mask=	0x000F
	RCODE_shift=	0

	hdr['QR']= not not(res[1] & QR)
	hdr['OpCode']= opcode_to_text((res[1] & Opcode_mask) >> Opcode_shift)
	hdr['AA']= not not(res[1] & AA)
	hdr['TC']= not not(res[1] & TC)
	hdr['RD']= not not(res[1] & RD)
	hdr['RA']= not not(res[1] & RA)
	hdr['Z']=  not not(res[1] & Z)
	hdr['AD']=  not not(res[1] & AD)
	hdr['CD']=  not not(res[1] & CD)
	hdr['ReturnCode']= rcode_to_text((res[1] & RCODE_mask) >> RCODE_shift)
	hdr['QDCOUNT']= res[2]
	hdr['ANCOUNT']= res[3]
	hdr['NSCOUNT']= res[4]
	hdr['ARCOUNT']= res[5]
	return (offset+reqlen, hdr)

def do_query(buf, offset):
	qry={}
	offset, name= do_name(buf, offset)
	qry['Qname']= name

	fmt= "!HH"
	reqlen= struct.calcsize(fmt)
	str= buf[offset:offset+reqlen]
	res= struct.unpack(fmt, str)
 	qry['Qtype']= type_to_text(res[0])
	qry['Qclass']= class_to_text(res[1])

	offset= offset+reqlen

	return offset, qry

def do_rr(buf, offset):
#       TYPE_EDNS0     = 41 # This is also OPT in type_to_text function
        EDNS0_OPT_NSID = 3  # this is also hardcoded in dns.edns.py
        error          = []
	rr             = {}
	res= do_name(buf, offset)
	if res == None:
		e= ("do_rr", offset, "do_name failed")
		error.append(e)
		return None
	offset, name= res
	rr['Name']= name
	fmt= "!HHIH"
	reqlen= struct.calcsize(fmt)
	dat= buf[offset:offset+reqlen]
	res= struct.unpack(fmt, dat)
        rr['Type']= type_to_text(res[0])
	rr['Class']= class_to_text(res[1])
	rr['TTL']= res[2]
	rr['RDlength']= res[3]

	offset= offset+reqlen

	rdata= buf[offset:offset+rr['RDlength']]
        rdata_offset= offset

	offset= offset+rr['RDlength']

#	if rr['Type'] == TYPE_EDNS0: # This is our internal method
	if rr['Type'] == 'OPT':      # this is per type_to_text function
		edns0= {}
		edns0['UDPsize']= res[1]
		edns0['ExtendedReturnCode']= res[2] >> 24
		edns0['Version']= (res[2] and 0x0f00) >> 16
                edns0['Z']= (res[2] and 0x00ff)
                edns0['Type']= 'OPT'
 		edns0['Option']= {}
                edns0['Name']= name
		
		# EDNS0 options
		o= 0
		while o < len(rdata):
			fmt= "!HH"
			reqlen= struct.calcsize(fmt)
			dat= rdata[o:o+reqlen]
			res= struct.unpack(fmt, dat)
			opt= {}
			opt['OptionCode']= res[0] 
			opt['OptionLength']= res[1]
			o=o+reqlen
			if opt['OptionCode'] == EDNS0_OPT_NSID:
				opt['OptionName']= 'NSID'
				opt[opt['OptionName']]= rdata[o:o+opt['OptionLength']]

			o=o+opt['OptionLength']
			edns0['Option'] = opt

                del rr['Class']
                del rr['RDlength']
                del rr['TTL']
                del rr['Name']
                del rr['Type']
                rr['EDNS0'] = edns0
	        return offset, rr

	if rr['Type'] == 'A' and rr['Class'] == "IN":      # this is per type_to_text function
	   fmt= "!BBBB"
	   a,b,c,d = struct.unpack(fmt, rdata)
           rr['Address'] = str(a)+'.'+str(b)+'.'+str(c)+'.'+str(d)

	if rr['Type'] == 'NS' and rr['Class'] == "IN":      # this is per type_to_text function
           doffset,name = do_name(buf,rdata_offset)
           rr['Target'] = name #rdata[2:rr['RDlength']-2]

	return offset, rr

def do_name(buf, offset):
	name=''
        error=[]
	while True:
		fmt= "!B"
		reqlen= struct.calcsize(fmt)
		str= buf[offset:offset+reqlen]
		if len(str) != reqlen:
			e= ("do_name", offset, ('offset out of range: buf size = %d') % len(buf))
			error.append(e)
			return None
		res= struct.unpack(fmt, str)
		llen= res[0]
		if llen <= 63:
			# Label
			offset= offset+1
			label= buf[offset:offset+llen]
			offset= offset+llen
			if name == '' or label != '':
				name= name + label + '.'
			if llen == 0:
				break
		elif llen >= 0xC0:
			fmt= "!H"
			reqlen= struct.calcsize(fmt)
			str= buf[offset:offset+reqlen]
			res= struct.unpack(fmt, str)
			poffset= res[0] & ~0xC000
			poffset, pname= do_name(buf, poffset)
			offset= offset + reqlen
			name= name + pname
			break
		else:
			#print 'do_name: bad count', llen
			return None
	return offset, name

def main(args):
    options = args.__dict__
    result  = {}
    result['line_count'] = 0
    result['decodedabufs_with_ERROR'] = 0
    result['abufdecode_failures'] = 0
    result['b64decode_failures'] = 0
    line = sys.stdin.readline()
    if args.verbosity >2:
       print "#inputline:\n#", line, "#end inputline-----"

    if line[:1] == "{" and line[-2:-1] == "}": # hson encoded data (RIPE Atlas measurment)
       while line:
          if args.verbosity >1:
             print "#json line:\n# ", line, "#end json line-----"
          result['line_count'] += 1
          result['errorFindingDecodingabuf'] = 0
          data = None
          try:
             data = json.loads(line)
             if data.has_key('result'):
                if data['result'].has_key('abuf'):
                   babuf = None
                   if args.verbosity >1:
                      print "#b64buf:\n#",data['result']['abuf'],"\n#end b64buf------"
                   try:
                      babuf = base64.b64decode(data['result']['abuf'])
                   except Exception:
                      result['b64decode_failures'] += 1;

                   if babuf:
                      adata  = decode_abuf(babuf, options) #, result)
                      if adata:
                         if data.has_key('ERROR'):
                            result['decodedabufs_with_ERROR'] += 1
                         data['DnsReply']= adata
          except Exception:
             line = sys.stdin.readline()
             continue
             error = []
             e = ("Error finding/decoding abuf")
             error.append(e)
             print "error:", error
             data['ERROR'] = error
             result['errorFindingDecodingabuf'] += 1

          if args.formattedJSON:
             print json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
          else:
             print json.dumps(data)

          line = sys.stdin.readline()
 
    else: # plain b64 encoced abuf
       while line:
          if args.verbosity >1:
             print "#b64 encoded abuf line:\n#", line, "#end b64 encoded abuf line-----"
          result['line_count'] += 1

          try:
             babuf = base64.b64decode(line)
          except Exception:
             result['b64decode_failures'] += 1;
             line = sys.stdin.readline()
             continue

          data  = decode_abuf(babuf, options) #, result)

          if data:
             if data.has_key('ERROR'):
                result['decodedabufs_with_ERROR'] += 1
             if args.formattedJSON:
                print json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
             else:
                print json.dumps(data)
                #print "data", data
          else:
             result['abufdecode_failures'] += 1

          line = sys.stdin.readline()

    if args.verbosity:
       import string
       print "#======== results:\n#",
       lines = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
       print string.replace(lines, "\n", "\n#") # we want this to be comments lines on stdout
#      print json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
    sys.stdout.flush()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v',    '--verbosity',     default=0,    action="count")
    parser.add_argument('-fj',   '--formattedJSON', default=0,    action="count")
    parser.add_argument('-dh',   '--DO_Header',     default=0,    action="count")
    parser.add_argument('-dq',   '--DO_Question',   default=0,    action="count")
    parser.add_argument('-dan',  '--DO_Answer',     default=0,    action="count")
    parser.add_argument('-dad',  '--DO_Additional', default=0,    action="count")
    parser.add_argument('-dau',  '--DO_Authority',  default=0,    action="count")
    parser.add_argument('-do',   '--DO_Options',    default=0,    action="count")
    parser.add_argument('-dall', '--DO_All',        default=0,    action="count")
    args = parser.parse_args()
    if args.DO_All:
       args.DO_Header     = 1
       args.DO_Question   = 1
       args.DO_Answer     = 1
       args.DO_Additional = 1
       args.DO_Authority  = 1
       args.DO_Options    = 1
       
    sys.exit(main(args))
