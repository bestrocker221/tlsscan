import logging, datetime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socket, timeit
from colors import *
from concurrent.futures import ProcessPoolExecutor, as_completed,ThreadPoolExecutor
from time import sleep,time

#
# Test if target is reachable otherwise abort
#
def checkConnection(target):
		try:
			#socket.setdefaulttimeout(3)
			socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(target)
			return True
		except Exception as ex:
			print "\n" + str(ex)
			if ex.errno == 111:
				print "\nHost or port unavailable\n"
			return False

#
# Create and return a socket with the target ( hostname, port ) selected.
#
def TCPConnect(target):
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	try:
		sock.connect(target)
	except socket.error, msg:
		print "Couldnt connect with the socket-server: %s\n" % msg
		exit(1)
	return sock


# 
# Function that deliver ClientHello and return the server response if any
#
# parameters = ( target, cipher_code, TLSversion,
#         tls_fallback_enabled, compression_enabled )
# 
# return (version, server_response) if accepted else None
# 
def send_client_hello(parameters):
	target = parameters[0]
	cipher_code = parameters[1]
	ver = parameters[2]
	tls_fallback = parameters[3]
	compression = parameters[4]
	secure_reneg = parameters[5]
	time_to_wait = parameters[6]

	if 0x5600 in cipher_code and not tls_fallback:
		cipher_code.remove(0x5600)
	else:
		cipher_code.append(0x5600)
	
	#cipher_code.remove(0x5600) if (0x5600 in cipher_code and not tls_fallback) else cipher_code.append(0x5600)
	compression = range(1,0xff) if compression else 0x00

	sock = TCPConnect(target)
	packet = TLSRecord(version="TLS_1_0")/\
				TLSHandshake()/\
				TLSClientHello(version=ver,
							compression_methods=compression,
							cipher_suites=cipher_code,)

	if secure_reneg:
		packet.getlayer(TLSClientHello).extensions = TLSExtension()/TLSExtRenegotiationInfo()
	sleep(float(time_to_wait)/1000)
	sock.sendall(str(packet))
	try:
		resp = sock.recv(10240)
	except socket.error as msg:
		"socket error: " + str(msg.errno)
		return None
	sock.close()

	ssl_p = SSL(resp)
	if ssl_p.haslayer(TLSServerHello) or ssl_p.haslayer(TLSAlert):
		return (ver,resp)
	else:
		return None


#
# Function for multiprocessing request to server
# 
# parameters = ( target, cipher_code_list, TLSversion )
# 
# return (version, server_response) if accepted else None
# 
# Structure of ordered_cipher_list:
# Example
# { "TLS_1_0": [0x00,0x01]}
# 
def order_cipher_suites(parameters):
	target = parameters[0]
	cipher_code_list = parameters[1]
	version = parameters[2]

	time_to_wait = parameters[3]

	ordered_cipher_list = {}
	ordered_cipher_list.update({version:[]})
	go = True
	while go:
		#print "SCAN CIPHER TIME TO WAIT: " + str(time_to_wait)
		resp = send_client_hello((target, cipher_code_list, version,
					 SCAN_PARAMS.NO_TLS_FALLBACK,
					 SCAN_PARAMS.NO_COMPRESSION,
					 SCAN_PARAMS.NO_SECURE_RENEG,
					 time_to_wait))
		if resp != None:
			resp = SSL(resp[1])
			if resp.haslayer(TLSServerHello):
				accepted_cipher = resp.getlayer(TLSServerHello).cipher_suite
				ordered_cipher_list.get(version).append(accepted_cipher)
				cipher_code_list.remove(accepted_cipher)
			elif resp.haslayer(TLSAlert):
				if resp.getlayer(TLSAlert).description == 40:
					#handshake failure
					go = False
		else:
			go = False
	return (version,ordered_cipher_list)

class Event(object):
	class CODE:
		RC4 = 1
		MD5 = 2
		SHA = 3
		CBC = 4
		DHE = 5

	class LEVEL:
		RED = "RED"
		YELLOW = "YELLOW"
	def __init__(self, subject, level, description):
		self.level = level
		self.description = description
		self.subject = subject

class SCAN_PARAMS:
		COMPRESSION = TLS_FALLBACK = SECURE_RENEG = True
		NO_COMPRESSION =  NO_TLS_FALLBACK = NO_SECURE_RENEG = False

class TLSScanner(object):
	def __init__(self, target, time_delay):
		self.hostname = target[0]
		self.target = (socket.gethostbyname(self.hostname), target[1] )

		#timing variable
		self.time_delay = time_delay
		#function to calculate time to wait between requests
		#self.should_sleep = lambda: float((self.time_delay - (time() -self.last_request_time)) / 1000)

		self.PROTOS = [p for p in TLS_VERSIONS.values() if p.startswith("TLS_") or p.startswith("SSL_")]
		self.PROTOS = sorted(self.PROTOS, reverse=True)
		
		self.server_certificate = None
		
		# Structure of ordered_cipher_list:
		# Example
		# { "TLS_1_0": [0x00,0x01], "TLS_1_1":[0x32], ...}
		# { proto: [supp_ciphers], ... }
		self.accepted_ordered_ciphers = {}
		self.ACCEPTED_CIPHERS_LEN = 0

		self.TLS_FALLBACK_SCSV_SUPPORTED = None
		self.SECURE_RENEGOTIATION = None
		self.COMPRESSION_ENABLED = None
		
		#to define
		self.RESPONSES = []
		
		#list of ssl/tls supported protocol by the server
		self.SUPP_PROTO = []

		# Structure of events:
		# Event() list
		self.EVENTS = []
		

		if not checkConnection(self.target):
			sys.exit(1)

		print "TARGET: " + str(self.hostname) + " resolved to " + str(self.target[0]) +":"+ str(self.target[1])
		print "Date of the test: " + str(datetime.datetime.now())
		if self.time_delay > 0:
			print "Timing: %d millisec between each request." % self.time_delay
		print "\n"

	def _analize_certificate(self):
		print "analyzing server certificate...     ",
		a = timeit.default_timer()
		if self.server_certificate == None:
			print "error"
			sys.exit(1)

		
		

		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	def _scan_protocol_versions(self):
		print "scanning for supported protocol...  ",
		a = timeit.default_timer()
		for proto in self.PROTOS:
			error = 0
			#scan for accepted protocol and include SCSV fallback signal
			params = (self.target, range(0xff), proto, 
				SCAN_PARAMS.TLS_FALLBACK,
				SCAN_PARAMS.NO_COMPRESSION,
				SCAN_PARAMS.NO_SECURE_RENEG,
				self.time_delay)
			
			resp = send_client_hello(params)
			
			if resp == None:
				error = 1
			else:
				resp = SSL(resp[1])
				if resp.haslayer(TLSAlert):
					if resp[TLSAlert].description == 86:
						#signaling suite supported
						#print "INAPPROPRIATE_FALLBACK --> SERVER SUPPORT SCSV SIGNALING"
						self.TLS_FALLBACK_SCSV_SUPPORTED = True
					if resp[TLSAlert].description == 70:
						#Protocol not supported by server
						error = 1
					if resp[TLSAlert].description == 40:
						#Handshake failure
						error = 1
				elif resp.haslayer(TLSServerHello) and self.server_certificate != None:
					if resp.haslayer(TLSCertificate):
						self.server_certificate = resp.getlayer(TLSCertificate)
			if error != 0:
				self.RESPONSES.append("TLSRecord version: TLS_1_0 Handshake version: %s not supported" % proto)
			else:
				self.RESPONSES.append("TLSRecord version: TLS_1_0 Handshake version: %s supported" % proto)
				self.SUPP_PROTO.append(proto)

			if self.TLS_FALLBACK_SCSV_SUPPORTED == None:
				self.TLS_FALLBACK_SCSV_SUPPORTED = False

		self.SUPP_PROTO = sorted(self.SUPP_PROTO)
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	def _scan_compression(self):
		print "scanning for compression support...  ",
		a = timeit.default_timer()
		ver = self.SUPP_PROTO[::-1][0]

		#scan if compression is enabled (scan for every protocol?)
		params = (self.target, range(0xff), ver,
			SCAN_PARAMS.NO_TLS_FALLBACK,
			SCAN_PARAMS.COMPRESSION,
			SCAN_PARAMS.NO_SECURE_RENEG,
			self.time_delay)
		resp = send_client_hello(params)
		resp = SSL(resp[1])
		if resp.haslayer(TLSAlert):
			if resp[TLSAlert].description == 50:
				#server does not support TLS compression
				self.COMPRESSION_ENABLED = False
		elif resp.haslayer(TLSServerHello):
			#print "server sent hello back --> compression enabled"
			self.COMPRESSION_ENABLED = True
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	def _scan_secure_renegotiation(self):
		print "scanning for secure renegotiation extension..  ",
		a = timeit.default_timer()
		ver = self.SUPP_PROTO[::-1][0]
		params = (self.target, range(0xff),ver,
					SCAN_PARAMS.NO_TLS_FALLBACK,
					SCAN_PARAMS.NO_COMPRESSION,
					SCAN_PARAMS.SECURE_RENEG,
					self.time_delay)
		resp = send_client_hello(params)
		resp = SSL(resp[1])
		if resp.haslayer(TLSExtRenegotiationInfo):
			self.SECURE_RENEGOTIATION = True
		else:
			self.SECURE_RENEGOTIATION = False
		print "\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)
	
	def _find_bad_ciphers(self, version, cipher_list):
		
		event_list = []
		for cipher in cipher_list:
			if TLS_CIPHER_SUITES[cipher].endswith("MD5"):
				if Event.CODE.MD5 not in event_list:
					event_list.append(Event.CODE.MD5)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "cipher (%s): MD5 is deprecated and considered insecure" % cipher))
			if TLS_CIPHER_SUITES[cipher].endswith("SHA"):
				if Event.CODE.SHA not in event_list:
					event_list.append(Event.CODE.SHA)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.YELLOW, "SHA is deprecated and considered insecure"))
			if "_CBC_" in TLS_CIPHER_SUITES[cipher]:
				if Event.CODE.CBC not in event_list:
					event_list.append(Event.CODE.CBC)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.YELLOW, "CBC block mode is susceptible to attacks"))
			#TODO
			#
			#
			#
	#
	# Scan cipher suites accepted and ordered by server preference.
	#
	def _scan_cipher_suite_accepted(self):
		if len(self.SUPP_PROTO) == 0:
			self._scan_protocol_versions()
		print "ordering cipher suites based on server preference...   ",
		
		cipher_scan_list = {}
		for proto in self.SUPP_PROTO:
			cipher_scan_list.update({proto:TLS_CIPHER_SUITES.keys()})

		a = timeit.default_timer()

		parameters = []
		for proto in cipher_scan_list.keys():
			parameters.append((self.target, cipher_scan_list[proto], proto, self.time_delay))

		with ProcessPoolExecutor(max_workers=len(self.SUPP_PROTO)) as executor:
			for ordered_cipher_list in executor.map(order_cipher_suites, parameters):
				self.accepted_ordered_ciphers.update(ordered_cipher_list[1])
				self._find_bad_ciphers(ordered_cipher_list[0],ordered_cipher_list[1][ordered_cipher_list[0]])
				self.ACCEPTED_CIPHERS_LEN += len(ordered_cipher_list[1][ordered_cipher_list[0]])
		print "done. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Printing result of the test.
	#
	def _printResults(self):
		print "\n###########  PRINTING RESULTS  ###########\n"
		for i in self.RESPONSES:
			print i
		
		print "\nSUPPORTED PROTOCOLS FOR HANDSHAKE: ",
		for i in self.SUPP_PROTO:
			if i=="SSL_3_0" or i=="SSL_2_0":
				printRed(i)
			elif i=="TLS_1_0":
				printWarning(i)
			else:
				printGreen(i)

		print "\n\nAccepted cipher-suites (",
		printGreen(str(self.ACCEPTED_CIPHERS_LEN))
		print "/ %d ) Ordered by server preference." %(len(TLS_CIPHER_SUITES))

		for proto in self.accepted_ordered_ciphers.keys():
			print "\n" + str(proto) + " supports " + str(len(self.accepted_ordered_ciphers[proto])) + " cipher suites.\n"
			for cipher in self.accepted_ordered_ciphers[proto]:
				print "Protocol: %s -> %s (%s) supported." % (proto,TLS_CIPHER_SUITES[cipher], hex(cipher))
			for ev in self.EVENTS:
				if ev.subject == (proto+"_CIPHERS"):
					printRed("[*]ALERT: ")
					printOrange(ev.description) if ev.level == Event.LEVEL.RED else printWarning(ev.description)
					print "\n",

		if self.TLS_FALLBACK_SCSV_SUPPORTED != None:
			print "\n\nTLS_FALLBACK_SCSV supported? ",
			printGreen("True") if self.TLS_FALLBACK_SCSV_SUPPORTED else printRed("False")
		if self.COMPRESSION_ENABLED != None:
			print "\n\nTLS COMPRESSION enabled? ",
			printGreen("False") if not self.COMPRESSION_ENABLED else printRed("True")
		if self.SECURE_RENEGOTIATION != None:
			print "\n\nSECURE RENEGOTIATION supported?",
			printGreen("True") if self.SECURE_RENEGOTIATION else printRed("False")

		#ATTACKS
		print "\n\nPOODLE attack: ",
		printRed("potentially vulnerable") if "SSL_3_0" in self.SUPP_PROTO else printGreen("not vulnerable, SSLv3 disabled")


		print "\n\n\n"

	#
	# Start a comprehensive scan of the given website.
	#
	def _fullScan(self):
		print "\nStarting SSL/TLS test on %s --> %s:%d" % (self.hostname,self.target[0],self.target[1])
		print "TYPE SCAN:  FULL SCAN\n\n"
		self._scan_protocol_versions()
		self._scan_compression()
		self._scan_secure_renegotiation()
		self._scan_cipher_suite_accepted()
		print "\n ---------- SCAN FINISHED ----------\n"

'''	
def main():
	target = (sys.argv[1], int(sys.argv[2]))

	start_time = timeit.default_timer()
    
	scanner = TLSScanner(target)
	scanner._fullScan()
	scanner._printResults()

	print "Finished in --- %s seconds ---\n\n" % (timeit.default_timer()-start_time)

if __name__ == '__main__':
	if len(sys.argv)<=2:
		print ("Usage: <host> <port>")
		exit(1)
	main()
'''