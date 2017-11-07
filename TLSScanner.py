import socks, logging, datetime, socket, timeit, binascii, collections, requests
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from colors import *
from time import sleep,time
from concurrent.futures import ProcessPoolExecutor, as_completed,ThreadPoolExecutor
from OpenSSL import crypto
from asn1crypto.x509 import Certificate
#
# Test if target is reachable otherwise abort
#
def checkConnection(target, torify):
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
def TCPConnect(target, torify):
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
#         tls_fallback_enabled, compression_enabled,
#         secure_renegotiation, time_to_wait, serve_name )
# 
# return (version, server_response) if accepted else None
# 
def send_client_hello(parameters):
	serve_name = parameters[7]
	target = parameters[0]
	cipher_code = parameters[1]
	ver = parameters[2]
	tls_fallback = parameters[3]
	compression = parameters[4]
	secure_reneg = parameters[5]
	time_to_wait = parameters[6]

	torify = parameters[8]

	if 0x5600 in cipher_code and not tls_fallback:
		cipher_code.remove(0x5600)
	else:
		cipher_code.append(0x5600)
	
	#cipher_code.remove(0x5600) if (0x5600 in cipher_code and not tls_fallback) else cipher_code.append(0x5600)
	compression = range(1,0xff) if compression else 0x00

	sock = TCPConnect(target, torify)
	packet = TLSRecord(version="TLS_1_0")/\
				TLSHandshake()/\
				TLSClientHello(version=ver,
							compression_methods=compression,
							cipher_suites=cipher_code,
							extensions = [
									TLSExtension()/\
										TLSExtServerNameIndication(server_names=
											[TLSServerName(data=serve_name)],)
								])

	if secure_reneg:
		packet.getlayer(TLSClientHello).extensions.append(TLSExtension()/TLSExtRenegotiationInfo())
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
# parameters = ( target, cipher_code_list, TLSversion, timetowait, server_name )
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
	server_name = parameters[4]

	torify = parameters[5]

	ordered_cipher_list = {}
	ordered_cipher_list.update({version:[]})
	go = True
	while go:
		#print "SCAN CIPHER TIME TO WAIT: " + str(time_to_wait)
		resp = send_client_hello((target, cipher_code_list, version,
					 SCAN_PARAMS.NO_TLS_FALLBACK,
					 SCAN_PARAMS.NO_COMPRESSION,
					 SCAN_PARAMS.NO_SECURE_RENEG,
					 time_to_wait,
					 server_name,
					 torify))
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
	class MODE:
		FULLSCAN = "FULLSCAN",
		CERTSCAN = "CERTSCAN",
		SUPPROTO = "SUPPROTO",
		CIPHERS  = "CIPHERS"

	def __init__(self, target, time_delay, verbose, to_file, torify):
		self.hostname = target[0]
		self.verbose = verbose
		self.to_file = to_file

		self.requests_session = requests.session()
		self.torify = torify
		if self.torify:
			self._set_tor_proxy()
		self.target = (socket.gethostbyname(self.hostname), target[1])
		self.scan_mode = None
		#timing variable
		self.time_delay = time_delay

		self.PROTOS = [p for p in TLS_VERSIONS.values() if p.startswith("TLS_") or p.startswith("SSL_")]
		self.PROTOS = sorted(self.PROTOS, reverse=True)
		
		self.server_certificate = None
		self.certificate_chain = []
		# Structure of ordered_cipher_list:
		# Example
		# { "TLS_1_0": [0x00,0x01], "TLS_1_1":[0x32], ...}
		# { proto: [supp_ciphers], ... }
		self.accepted_ordered_ciphers = {}
		self.ACCEPTED_CIPHERS_LEN = 0

		self.TLS_FALLBACK_SCSV_SUPPORTED = None
		self.SECURE_RENEGOTIATION = None
		self.COMPRESSION_ENABLED = None
		self.bad_sni_check = None
		self.hsts = None
		self.http_status_code = None

		#to define
		self.RESPONSES = []
		
		#list of ssl/tls supported protocol by the server
		self.SUPP_PROTO = []

		# Structure of events:
		# Event() list
		self.EVENTS = []

		if not checkConnection(self.target, self.torify):
			sys.exit(1)

		print "TARGET: " + str(self.hostname) + " resolved to " + str(self.target[0]) +":"+ str(self.target[1])
		print "Date of the test: " + str(datetime.datetime.now())
		if self.time_delay > 0:
			print "Timing: %d millisec between each request." % self.time_delay
		print "\n"
		#self.bogus()
		#self. _check_hsts()
		#self.print_results()
		#self.scan_protocol_versions()
		#self._check_bad_sni_response()
	

	def _set_tor_proxy(self):
		print "Checking tor proxy connectivity...   "
		if not checkConnection(("127.0.0.1", 9050), False):
			print "TOR PROXY NOT RUNNING\n"
			exit(1)
		else:
			socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
			print "TOR PROXY RUNNING ON PORT 9050\n"
			#setting global socket setting to use socks.socksocket
			socket.socket = socks.socksocket
			self.requests_session.proxies = {
				'http':'socks5h://127.0.0.1:9050',
				'https':'socks5h://127.0.0.1:9050'
			}
			#url to get ext ip
			url = "http://icanhazip.com"
			response = self.requests_session.get(url)
			print "TOR IP: ", response.text

	def _textColor(self, txt, color):
		return txt if (self.to_file != None) else textColor(txt,color)

	def bogus(self):
		print "OOOOOOOOOOOOOOOOOO"
		
		#exit(0)

		sock = TCPConnect(self.target, self.torify)
		packet = TLSRecord(version="TLS_1_0")/\
					TLSHandshake()/\
					TLSClientHello(version="TLS_1_2",
								compression_methods=0x00,
								cipher_suites=range(0xff),
								extensions = [
									TLSExtension()/\
										TLSExtServerNameIndication(server_names=
											[TLSServerName(data="mycalitrip.ddns.net")],)
								])
		#packet.getlayer(TLSClientHello).extensions = TLSExtension()/\
		#		TLSExtServerNameIndication(server_names=[TLSServerName(data="mycalitrip.ddns.net")])
		sock.sendall(str(packet))
		try:
			resp = sock.recv(10240)
		except socket.error as msg:
			"socket error: " + str(msg.errno)
			return None
		sock.close()
		resp = SSL(resp)
		print textColor("ciao\nciao", bcolors.RED)
		exit(0)

	
	def _analyze_certificates(self):
		if len(self.SUPP_PROTO) == 0:
			self._scan_protocol_versions()

		if self.server_certificate == None:
			print "error, try again"
			sys.exit(1)

	def _save_cert_chain(self, TLSCertificateList):
		print "loading certificate chain...         ",
		a = timeit.default_timer()

		for cert in TLSCertificateList.certificates:
			c = Certificate.load(bytes(cert.data))
			self.certificate_chain.append(c)

		self.server_certificate = self.certificate_chain[0]
		#print self.server_certificate
		#exit(1)
		
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	def _check_bad_sni_response(self):
		print "checking bad sni response...         ",
		a = timeit.default_timer()
		bogus_hostname = "www.bogus-address.com"

		ver = self.SUPP_PROTO[::-1][0]
		params = (self.target, range(0xff),ver , 
				SCAN_PARAMS.TLS_FALLBACK,
				SCAN_PARAMS.NO_COMPRESSION,
				SCAN_PARAMS.NO_SECURE_RENEG,
				self.time_delay,
				bogus_hostname,
				self.torify)
		ver,resp = send_client_hello(params)
		if resp != None:
			resp = SSL(resp)
			if resp.haslayer(TLSCertificate):
				cert = Certificate.load(bytes(resp.getlayer(TLSCertificate).data))
				cert_hostnames = cert.valid_domains
				self.bad_sni_check = bogus_hostname in cert_hostnames
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	def _scan_protocol_versions(self):
		print "scanning for supported protocol...  ",
		a = timeit.default_timer()
		cert_list = None
		for proto in self.PROTOS:
			error = 0
			#scan for accepted protocol and include SCSV fallback signal
			params = (self.target, range(0xff), proto, 
				SCAN_PARAMS.TLS_FALLBACK,
				SCAN_PARAMS.NO_COMPRESSION,
				SCAN_PARAMS.NO_SECURE_RENEG,
				self.time_delay,
				self.hostname,
				self.torify)
			
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
				elif resp.haslayer(TLSCertificateList) and cert_list == None:
					cert_list = resp.getlayer(TLSCertificateList)
					#self._save_cert_chain(resp.getlayer(TLSCertificateList))
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

		if cert_list != None:
			self._save_cert_chain(cert_list)
		else:
			print "error.. server didnt send certificate"
			exit(1)

	def _scan_compression(self):
		print "scanning for compression support...  ",
		a = timeit.default_timer()
		ver = self.SUPP_PROTO[::-1][0]

		#scan if compression is enabled (scan for every protocol?)
		params = (self.target, range(0xff), ver,
			SCAN_PARAMS.NO_TLS_FALLBACK,
			SCAN_PARAMS.COMPRESSION,
			SCAN_PARAMS.NO_SECURE_RENEG,
			self.time_delay,
			self.hostname,
			self.torify)
		ver, resp = send_client_hello(params)
		resp = SSL(resp)
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
					self.time_delay,
					self.hostname,
					self.torify)
		ver, resp = send_client_hello(params)
		resp = SSL(resp)
		self.SECURE_RENEGOTIATION = True if resp.haslayer(TLSExtRenegotiationInfo) else False
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
			parameters.append((self.target, cipher_scan_list[proto], proto, self.time_delay, self.hostname, self.torify))

		with ProcessPoolExecutor(max_workers=len(self.SUPP_PROTO)) as executor:
			for version, ordered_cipher_list in executor.map(order_cipher_suites, parameters):
				self.accepted_ordered_ciphers.update(ordered_cipher_list)
				self._find_bad_ciphers(version,ordered_cipher_list[version])
				self.ACCEPTED_CIPHERS_LEN += len(ordered_cipher_list[version])
		print "done. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Make a HEAD request to the server and analyze headers returned.
	# Look for HTTP Strict Transport Security header
	#
	def _check_hsts(self):
		print "looking for HSTS header...           ",
		a = timeit.default_timer()
		headers = {
    		'cache-control': "no-cache"
		}
		url = "https://" + self.hostname
		response = self.requests_session.head(url, headers=headers)
		self.hsts = response.headers["Strict-Transport-Security"] if ("Strict-Transport-Security" in response.headers.keys()) else None
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Print result for HSTS header request.
	#
	def _print_hsts_results(self):
		print "\nHTTP Strict Transport Security enabled? ",
		if self.hsts != None:
			print self._textColor("YES", bcolors.OKGREEN)
			print "\tHeader: ", self._textColor(self.hsts, bcolors.OKGREEN)
			print "\tInclude subdomains? ", self._textColor("YES", bcolors.OKGREEN) if ("includesubdomains" in self.hsts.lower()) else self._textColor("NO", bcolors.FAIL)
			print "\tPreloaded? ", self._textColor("YES", bcolors.OKGREEN) if ("preload" in self.hsts.lower()) else self._textColor("NO", bcolors.FAIL)
		else:
			print self._textColor("NO", bcolors.FAIL)

	#
	# Print certificate information.
	#
	def _print_certificate_info(self, certificate):
		#tbs_cert = self.server_certificate.native["tbs_certificate"]
		#sig_alg = self.server_certificate.native["signature_algorithm"]
		#sig_value = self.server_certificate.native["signature_value"]
		tbs_cert = certificate.native["tbs_certificate"]

		print "\n################# CERTIFICATE INFORMATION for %s #################\n" % tbs_cert["subject"]["common_name"]
		
		if self.verbose:
			print "Version:\t" + str(tbs_cert["version"])
			print "Serial Number:\t" + str(tbs_cert["serial_number"])
			print "Signature Algorithm:\t" + tbs_cert["signature"]["algorithm"]
			print "Issuer:"
			for i in tbs_cert["issuer"]:
				print "\t",i,":", tbs_cert["issuer"][i]
			print "Validity:"
			for i in tbs_cert["validity"]:
				print "\t",i,":", tbs_cert["validity"][i]
			print "Subject:"
			for i in tbs_cert["subject"]:
				print "\t",i,":", tbs_cert["subject"][i]
			print "Subject public key info:"
			for i in tbs_cert["subject_public_key_info"]:
				print "\t",i,":"
				for info in tbs_cert["subject_public_key_info"][i]:
					print "\t\t",info,":", tbs_cert["subject_public_key_info"][i][info]
			print "Extensions:"
			for i in certificate["tbs_certificate"]["extensions"]:
				print "\tName: ", i["extn_id"].native + ",", 
				if bool(i["critical"]):
					print self._textColor("critical\n", bcolors.WARNING)
				else:
					print "non-critical"

			print "\nCertificate signature scheme: ", certificate.signature_algo
			#print "Certificate signature (hexlified):\n\t", binascii.hexlify(certificate.signature)

		print "Is certificate EXPIRED? ",
		nb = datetime.datetime.strptime(str(tbs_cert["validity"]["not_before"])[:-6], '%Y-%m-%d %H:%M:%S')
		na = datetime.datetime.strptime(str(tbs_cert["validity"]["not_after"])[:-6], '%Y-%m-%d %H:%M:%S')
		now = datetime.datetime.strptime(str(datetime.datetime.now())[:-7], '%Y-%m-%d %H:%M:%S')
		if (now > nb and now < na):
			print self._textColor("NO, valid until " + str(na), bcolors.OKGREEN)
		else:
			print self._textColor("YES, expired on " + str(na), bcolors.RED)

		if not certificate.ca:
			print "Hostname match CN or SUBJECT_ALTERNATIVE_NAME?",
			if (self.hostname in tbs_cert["subject"]["common_name"] or self.hostname in certificate.valid_domains):
				print self._textColor("YES", bcolors.OKGREEN) 
			else:
				print self._textColor("NO", bcolors.RED)
		print "(Requested) ", self.hostname, " (Certificate)",tbs_cert["subject"]["common_name"]
		if not certificate.ca:
			print "Hostname matches with alternative name: ",
			if (self.hostname in certificate.valid_domains):
				print self._textColor(self.hostname, bcolors.OKGREEN)
			else:
				print self._textColor("Nothing", bcolors.RED)
		print "Is a CA certificate?",
		print "YES" if certificate.ca else "NO"
		print "Is a self-signed certificate? ", certificate.self_signed.upper()
		
		if self.verbose:
			print "CRL url: ", certificate.crl_distribution_points[0].url if (len(certificate.crl_distribution_points) > 0) else "NO CLR"
			print "OSCP url: ",certificate.ocsp_urls[0]
			print "Valid domains for certificate: ", certificate.valid_domains if (len(certificate.valid_domains) > 0) else "None"

	#
	# Printing supported protocols.
	#
	def _print_supproto(self):
		print "\n################# PROTOCOLS SUPPORTED #################\n"
		print "SUPPORTED PROTOCOLS FOR HANDSHAKE: ",
		for i in self.SUPP_PROTO:
			if i=="SSL_3_0" or i=="SSL_2_0":
				print self._textColor(i, bcolors.RED),
			elif i=="TLS_1_0":
				print self._textColor(i, bcolors.WARNING),
			else:
				print self._textColor(i, bcolors.OKGREEN),

	#
	# Printing cipher suites accepted.
	# 
	def _print_ciphers(self):
		print "\n\n################## CIPHER SUITES #################"
		if self.ACCEPTED_CIPHERS_LEN > 0:
			print "\n\nAccepted cipher-suites (",
			print self._textColor(str(self.ACCEPTED_CIPHERS_LEN), bcolors.OKGREEN),
			print "/ %d ) Ordered by server preference." %(len(TLS_CIPHER_SUITES))

			for proto in self.accepted_ordered_ciphers.keys():
				print "\n" + str(proto) + " supports " + str(len(self.accepted_ordered_ciphers[proto])) + " cipher suites.\n"
				for cipher in self.accepted_ordered_ciphers[proto]:
					print "Protocol: %s -> %s (%s) supported." % (proto,TLS_CIPHER_SUITES[cipher], hex(cipher))
				for ev in self.EVENTS:
					if ev.subject == (proto+"_CIPHERS"):
						print self._textColor("[*]ALERT: ", bcolors.RED),
						if ev.level == Event.LEVEL.RED:
							print self._textColor(ev.description, bcolors.FAIL) 
						else:
							print self._textColor(ev.description, bcolors.WARNING)

	#
	# Print if server sent back an alert for a bad SNI.
	#
	def _print_bad_sni_check(self):
		print "\nIncorrect Server Name Indication alert? ",
		print self._textColor("NO", bcolors.RED) if not self.bad_sni_check else self._textColor("YES", bcolors.OKGREEN)

	#
	# Printing result of the test.
	#
	def print_results(self):
		print "\n###########  PRINTING RESULTS  ###########\n"
		
		for i in self.RESPONSES:
			print i

		#printing certificate informations
		print "\nTotal number of certificates received: ", len(self.certificate_chain)
		for cert in self.certificate_chain:
			self._print_certificate_info(cert)
		
		#printing supported protocols
		self._print_supproto()

		#printing cipher suites accepted
		#TODO make prints based on mode
		if self.scan_mode == TLSScanner.MODE.CIPHERS or self.scan_mode == TLSScanner.MODE.FULLSCAN:
			self._print_ciphers()
		

		print "\n\n################## SECURITY OPTIONS #################"
		#printing support for SCSV
		if self.TLS_FALLBACK_SCSV_SUPPORTED != None:
			print "\nTLS_FALLBACK_SCSV supported? ",
			print self._textColor("True", bcolors.OKGREEN) if self.TLS_FALLBACK_SCSV_SUPPORTED else self._textColor("False", bcolors.RED)
		#printing support for compression
		if self.COMPRESSION_ENABLED != None:
			print "\nTLS COMPRESSION enabled? ",
			print self._textColor("False", bcolors.OKGREEN) if not self.COMPRESSION_ENABLED else self._textColor("True", bcolors.RED)
		#printing support for secure renegotiation extension
		if self.SECURE_RENEGOTIATION != None:
			print "\nSECURE RENEGOTIATION supported?",
			print self._textColor("True", bcolors.OKGREEN) if self.SECURE_RENEGOTIATION else self._textColor("False", bcolors.RED)
		
		#printing HSTS header info
		if self.hsts != None:
			self._print_hsts_results()
		#printing full support for sni
		if self.bad_sni_check != None:
			self._print_bad_sni_check()
		
		#ATTACKS
		print "\n\n################## ATTACKS #################"
		print "\nPOODLE attack: ",
		if "SSL_3_0" in self.SUPP_PROTO:
			print self._textColor("potentially vulnerable", bcolors.RED)
		else:
			print self._textColor("not vulnerable, SSLv3 disabled", bcolors.OKGREEN)


		print "\n\n\n"

	#
	# Start a comprehensive scan of the given website.
	#
	def full_scan(self):
		self._scan_protocol_versions()
		self._scan_compression()
		self._scan_secure_renegotiation()
		#self._scan_cipher_suite_accepted()
		
		self._check_bad_sni_response()
		self._check_hsts()

	def scan(self, mode):
		print "\nStarting SSL/TLS test on %s --> %s:%d" % (self.hostname,self.target[0],self.target[1])
		print "TYPE SCAN:  %s\n\n" % mode
		self.scan_mode = mode
		if mode == TLSScanner.MODE.FULLSCAN:
			self.full_scan()
		elif mode == TLSScanner.MODE.CIPHERS:
			self._scan_cipher_suite_accepted()
		elif mode == TLSScanner.MODE.SUPPROTO:
			self._scan_protocol_versions()
		elif mode == TLSScanner.MODE.CERTSCAN:
			self._analyze_certificates()

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