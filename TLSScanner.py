import socks, logging, datetime, socket, timeit, binascii, collections, requests
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from colors import *
from time import sleep,time
from concurrent.futures import ProcessPoolExecutor
from OpenSSL import crypto
from asn1crypto.x509 import Certificate

#
# Test if target is reachable otherwise abort
#
def checkConnection(target):
		try:
			#socket.setdefaulttimeout(3)
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(target)
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
# return (version, server_response) if accepted else None
# 
def send_client_hello(tls_scan_obj):
	if 0x5600 in tls_scan_obj.cipher_list and not tls_scan_obj.tls_fallback:
		tls_scan_obj.cipher_list.remove(0x5600)
	else:
		tls_scan_obj.cipher_list.append(0x5600)
	
	#cipher_code.remove(0x5600) if (0x5600 in cipher_code and not tls_fallback) else cipher_code.append(0x5600)
	compression = range(1,0xff) if tls_scan_obj.tls_compression else 0x00

	sock = TCPConnect(tls_scan_obj.target)
	packet = TLSRecord(version="TLS_1_0")/\
				TLSHandshake()/\
				TLSClientHello(version=tls_scan_obj.version,
							compression_methods=compression,
							cipher_suites=tls_scan_obj.cipher_list,
							extensions = [
									TLSExtension()/\
										TLSExtServerNameIndication(server_names=
											[TLSServerName(data=tls_scan_obj.server_name)],)
								])

	if tls_scan_obj.tls_sec_reneg:
		packet.getlayer(TLSClientHello).extensions.append(TLSExtension()/TLSExtRenegotiationInfo())
	if tls_scan_obj.tls_heartbeat:
		packet.getlayer(TLSClientHello).extensions.append(TLSExtension()/TLSExtHeartbeat())
	if tls_scan_obj.ocsp:
		packet.getlayer(TLSClientHello).extensions.append(TLSExtension()/TLSExtCertificateStatusRequest())
	if tls_scan_obj.session_ticket:
		packet.getlayer(TLSClientHello).extensions.append(TLSExtension()/TLSExtSessionTicketTLS())

	sleep(float(tls_scan_obj.time_to_wait)/1000)
	sock.sendall(str(packet))
	try:
		resp = sock.recv(10240)
	except socket.error as msg:
		"socket error: " ,msg.message
		return None
	
	if tls_scan_obj.tls_heartbleed:
		p = TLSRecord(version=tls_scan_obj.version)/TLSHeartBeat(length=2**14-1,data='bleeding...')
		sock.settimeout(1)
		sock.sendall(str(p))
		try:
			resp = sock.recv(8192)
		except (socket.timeout, socket.error) as msg:
			#print "ERROR: ", msg, type(str(msg))
			return (tls_scan_obj.version, str(msg))	
		sock.close()
		return (tls_scan_obj.version, resp)

	sock.close()
	ssl_p = SSL(resp)
	#ssl_p.show()
	if ssl_p.haslayer(TLSServerHello) or ssl_p.haslayer(TLSAlert) or ssl_p.haslayer(TLSCertificate):
		return (tls_scan_obj.version,resp)
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
def order_cipher_suites(tls_scan_obj):
	ordered_cipher_list = {}
	ordered_cipher_list.update({tls_scan_obj.version:[]})

	go = True
	while go:
		#print "SCAN CIPHER TIME TO WAIT: " + str(time_to_wait)
		resp = send_client_hello(tls_scan_obj)
		if resp != None:
			resp = SSL(resp[1])
			if resp.haslayer(TLSServerHello):
				accepted_cipher = resp.getlayer(TLSServerHello).cipher_suite
				ordered_cipher_list.get(tls_scan_obj.version).append(accepted_cipher)
				tls_scan_obj.cipher_list.remove(accepted_cipher)
			elif resp.haslayer(TLSAlert):
				if resp.getlayer(TLSAlert).description == 40:
					#handshake failure
					go = False
		else:
			go = False
	return (tls_scan_obj.version,ordered_cipher_list)

class Event(object):
	class CODE:
		RC4 = 1
		MD5 = 2
		SHA = 3
		CBC = 4
		DHE = 5
		BEAST = 6
		EXPORT = 7
		DES = 8

	class LEVEL:
		RED = "RED"
		YELLOW = "YELLOW"
		WHITE = "WHITE"
	def __init__(self, subject, level, description):
		self.level = level
		self.description = description
		self.subject = subject

class TLSScanObject(object):
	def __init__(self, target, server_name, cipher_list=range(0xff), version="TLS_1_1", tls_fallback=False, ocsp=False,
					tls_compression=False, tls_sec_reneg=False, tls_heartbeat=False, tls_heartbleed=False,
					session_ticket=False, time_to_wait=0):
		self.target = target
		self.cipher_list = cipher_list
		self.version=version
		self.tls_fallback = tls_fallback
		self.tls_compression = tls_compression
		self.tls_sec_reneg = tls_sec_reneg
		self.tls_heartbeat = tls_heartbeat
		self.tls_heartbleed = tls_heartbleed
		self.time_to_wait = time_to_wait
		self.server_name = server_name

		self.ocsp = ocsp
		self.session_ticket = session_ticket

class TLSScanner(object):
	class MODE:
		FULLSCAN = "FULLSCAN",
		CERTSCAN = "CERTSCAN",
		SUPPROTO = "SUPPROTO",
		CIPHERS  = "CIPHERS"

	def __init__(self, target, time_delay, verbose, to_file, torify):
		self.hostname = target[0]
		self.dest_ip = None
		self.port = target[1]
		self.verbose = verbose
		self.to_file = to_file

		self.requests_session = requests.session()
		self.torify = torify
		if self.torify:
			self._set_tor_proxy()
		self.target = self._maket_target()
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
		self.tls_heartbeat = None
		self.tls_heartbleed = None
		self.tls_session_tickets = None

		self.tls_beast = False
		self.rc4_enabled = False
		self.poodle = False
		self.export_ciphers = False

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
		
		if not checkConnection((self.hostname, self.port)):
			sys.exit(1)

		print "TARGET: " + str(self.hostname) + " resolved to " + str(self.target[0]) +":"+ str(self.port)
		print "Date of the test: " + str(datetime.datetime.now())
		if self.time_delay > 0:
			print "Timing: %d millisec between each request." % self.time_delay
		print "\n"
		#self.bogus()
		#self. _check_hsts()
		#self.print_results()
		#self.scan_protocol_versions()
		#self._check_bad_sni_response()
		#self._check_heartbeat()
		#self._check_heartbleed()
		#self._check_ocsp()
		#self._check_session_ticket()
	
	def _maket_target(self):
		try:
			return (socket.gethostbyname(self.hostname) if not self.torify
							else self.hostname, self.port)
		except socket.gaierror as err:
			if err.errno == -2:
				print "Host does not resolve to a valid IP\nPlease try again with a correct hostname\n\n"
			else:
				print err
			exit(1)

	def _check_session_ticket(self):
		if len(self.SUPP_PROTO) == 0:
			self._scan_protocol_versions()
		print "checking TLS session ticket support..",
		ver = self.SUPP_PROTO[::-1][0]
		a = timeit.default_timer()

		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self.hostname, session_ticket=True)
		ver, resp = send_client_hello(tls_scan_obj)
		resp = SSL(resp)
		self.tls_session_tickets = False
		for ext in resp.getlayer(TLSServerHello).extensions:
			if ext.type == 35:
				#session ticket supported
				self.tls_session_tickets = True
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	def _check_ocsp(self):
		print "checking ocsp"
		if len(self.SUPP_PROTO) == 0:
			self._scan_protocol_versions()
			if "TLS_1_1" not in self.SUPP_PROTO or "TLS_1_2" not in self.SUPP_PROTO:
				self.tls_heartbeat = False
				return
		print "checking TLS heartbeat extension...  ",
		ver = self.SUPP_PROTO[::-1][0]
		a = timeit.default_timer()

		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self.hostname, ocsp=True)
		ver, resp = send_client_hello(tls_scan_obj)
		resp = SSL(resp)


		exit(1)


	def _set_tor_proxy(self):
		print "Checking tor proxy connectivity...   "
		if not checkConnection(("127.0.0.1", 9050)):
			print "TOR PROXY NOT RUNNING\n"
			exit(1)
		else:
			socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
			print "TOR PROXY RUNNING ON PORT 9050\n"
			#setting global socket setting to use socks.socksocket
			socket.socket = socks.socksocket
			#socket.getaddrinfo = getaddrinfo

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
		print textColor("ciao\nciao", bcolors.FAIL)
		exit(0)

	def _check_heartbeat(self):
		if len(self.SUPP_PROTO) == 0:
			self._scan_protocol_versions()
			if "TLS_1_1" not in self.SUPP_PROTO or "TLS_1_2" not in self.SUPP_PROTO:
				self.tls_heartbeat = False
				return
		print "checking TLS heartbeat extension...  ",
		ver = self.SUPP_PROTO[::-1][0]
		a = timeit.default_timer()

		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self.hostname, tls_heartbeat=True)
		ver, resp = send_client_hello(tls_scan_obj)
		resp = SSL(resp)

		self.tls_heartbeat = True if resp.haslayer(TLSExtHeartbeat) else False

		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)
		if self.tls_heartbeat:
			self._check_heartbleed()

	def _check_heartbleed(self):
		print "checking TLS heartbleed...           ", 
		ver = self.SUPP_PROTO[::-1][0]
		a = timeit.default_timer()
		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self.hostname, tls_heartbleed=True)
		ver, resp = send_client_hello(tls_scan_obj)		
		resp2 = SSL(resp)
		
		self.tls_heartbleed = False
		if len(resp) == 0:
			#print "nothing returned"
			pass
		elif resp == str(104):
			#print "connection reset by peer"
			pass
		elif resp == "timed out":
			#connection timed out, probably not vulnerable
			pass
		elif resp2.haslayer(TLSAlert):
			if resp2.getlayer(TLSAlert).description == 10:
				pass
				#unexpected msg
		else:
			with file("bleed_" + self.hostname + ".txt", "w") as f:
				f.write(repr(resp))
			self.tls_heartbleed = "bleed_" + self.hostname + ".txt"

		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

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
		tls_scan_obj = TLSScanObject(target=self.target, server_name=bogus_hostname, version=ver, tls_fallback=False)
		ver,resp = send_client_hello(tls_scan_obj)
		if resp != None:
			resp = SSL(resp)
			if resp.haslayer(TLSCertificate):
				cert = Certificate.load(bytes(resp.getlayer(TLSCertificate).data))
				cert_hostnames = cert.valid_domains
				#very basic check on hostname match
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
			tls_scan_obj = TLSScanObject(target=self.target, server_name=self.hostname, version=proto,
											tls_fallback=True, time_to_wait=self.time_delay)
			resp = send_client_hello(tls_scan_obj)
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
		tls_scan_obj = TLSScanObject(target=self.target, server_name=self.hostname, version=ver, tls_compression=True,
										time_to_wait=self.time_delay)
		ver, resp = send_client_hello(tls_scan_obj)
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
		tls_scan_obj = TLSScanObject(target=self.target, server_name=self.hostname, version=ver, tls_sec_reneg=True,
										time_to_wait=self.time_delay)
		ver, resp = send_client_hello(tls_scan_obj)
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
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.YELLOW, "SHA should be upgraded to SHA-2"))
			if "_CBC_" in TLS_CIPHER_SUITES[cipher] and version == "SSL_3_0":
				if Event.CODE.POODLE not in event_list:
					event_list.append(Event.CODE.POODLE)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "CBC and SSL_3 are vulnerable to POODLE attack!"))
					self.poodle = True
			if "_CBC_" in TLS_CIPHER_SUITES[cipher] and (version == "TLS_1_0" or version == "SSL_3_0"):
				if Event.CODE.BEAST not in event_list:
					event_list.append(Event.CODE.BEAST)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.WHITE, version + " and CBC could lead to BEAST attack! (if not client mitigated)"))
					self.tls_beast = True
			if "RC4" in TLS_CIPHER_SUITES[cipher]:
				if Event.CODE.RC4 not in event_list:
					event_list.append(Event.CODE.RC4)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "RC4 in known to be insecure and deprecated"))
					self.rc4_enabled = True
			if "DES" in TLS_CIPHER_SUITES[cipher]:
				if Event.CODE.DES not in event_list:
					event_list.append(Event.CODE.DES)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.YELLOW, "DES/3DES considered weak, could disable."))
			if "EXPORT" in TLS_CIPHER_SUITES[cipher]:
				if Event.CODE.EXPORT not in event_list:
					event_list.append(Event.CODE.EXPORT)
					self.EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "EXPORT ciphers could lead to Logjam and FREAK"))
					self.export_ciphers = True
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
			tls_scan_obj = TLSScanObject(target=self.target, server_name=self.hostname, version=proto,
											cipher_list=cipher_scan_list[proto], time_to_wait=self.time_delay)
			parameters.append(tls_scan_obj)
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
		#disabling warning, we want just to know if hsts is supported.
		requests.urllib3.disable_warnings()
		#disabling certificate verification
		response = self.requests_session.head(url, headers=headers, verify=False)
		self.hsts = response.headers["Strict-Transport-Security"] if ("Strict-Transport-Security" in response.headers.keys()) else False
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Print result for HSTS header request.
	#
	def _print_hsts_results(self):
		print "\n[*]HTTP Strict Transport Security enabled? ",
		if self.hsts:
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
		
		print "Signature Algorithm:\t",
		signature = tbs_cert["signature"]["algorithm"].lower()
		if "sha1" in signature or "md5" in signature:
			print self._textColor(signature, bcolors.FAIL)
		else:
			print self._textColor(signature, bcolors.OKGREEN)
		if self.verbose:
			print "Version:\t" + str(tbs_cert["version"])
			print "Serial Number:\t" + str(tbs_cert["serial_number"])
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

			print "\n[*]Certificate signature scheme: ", certificate.signature_algo
			#print "Certificate signature (hexlified):\n\t", binascii.hexlify(certificate.signature)

		print "[*]Is certificate EXPIRED? ",
		nb = datetime.datetime.strptime(str(tbs_cert["validity"]["not_before"])[:-6], '%Y-%m-%d %H:%M:%S')
		na = datetime.datetime.strptime(str(tbs_cert["validity"]["not_after"])[:-6], '%Y-%m-%d %H:%M:%S')
		now = datetime.datetime.strptime(str(datetime.datetime.now())[:-7], '%Y-%m-%d %H:%M:%S')
		if (now > nb and now < na):
			print self._textColor("NO, valid until " + str(na), bcolors.OKGREEN)
		else:
			print self._textColor("YES, expired on " + str(na), bcolors.FAIL)

		if not certificate.ca:
			print "[*]Hostname match CN or SUBJECT_ALTERNATIVE_NAME?",
			if (self.hostname in tbs_cert["subject"]["common_name"] or self.hostname in certificate.valid_domains):
				print self._textColor("YES", bcolors.OKGREEN) 
			else:
				print self._textColor("NO", bcolors.FAIL)
		print "(Requested) ", self.hostname, " (Certificate)",tbs_cert["subject"]["common_name"]
		if not certificate.ca:
			print "[*]Hostname matches with alternative name: ",
			if (self.hostname in certificate.valid_domains):
				print self._textColor(self.hostname, bcolors.OKGREEN)
			else:
				print self._textColor("Nothing", bcolors.FAIL)
		print "[*]Is a CA certificate?",
		print "YES" if certificate.ca else "NO"
		print "[*]Is a self-signed certificate? ", certificate.self_signed.upper()
		
		if self.verbose:
			print "[*]CRL url: ", certificate.crl_distribution_points[0].url if (len(certificate.crl_distribution_points) > 0) else "NO CLR"
			print "[*]OSCP url: ",certificate.ocsp_urls[0]
			print "[*]Valid domains for certificate: ", certificate.valid_domains if (len(certificate.valid_domains) > 0) else "None"

	#
	# Printing supported protocols.
	#
	def _print_supproto(self):
		print "\n################# PROTOCOLS SUPPORTED #################\n"
		print "SUPPORTED PROTOCOLS FOR HANDSHAKE: ",
		for i in self.SUPP_PROTO:
			if i=="SSL_3_0" or i=="SSL_2_0":
				print self._textColor(i, bcolors.FAIL),
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
					print "Protocol: %s -> %s (%s) supported." % (proto,TLS_CIPHER_SUITES[cipher], hex(cipher)),
					print self._textColor("FS", bcolors.OKGREEN) if "RSA" not in TLS_CIPHER_SUITES[cipher].split("_")[0] else self._textColor("non FS", bcolors.FAIL)
				for ev in self.EVENTS:
					if ev.subject == (proto+"_CIPHERS"):
						print self._textColor("[*]ALERT: ", bcolors.FAIL),
						if ev.level == Event.LEVEL.RED:
							print self._textColor(ev.description, bcolors.FAIL) 
						else:
							print self._textColor(ev.description, bcolors.WARNING)
		print "\n\tFS = Forward Secrecy"

	#
	# Print if server sent back an alert for a bad SNI.
	#
	def _print_bad_sni_check(self):
		print "\n[*]Incorrect Server Name Indication alert? ",
		print "NO" if not self.bad_sni_check else self._textColor("YES", bcolors.OKGREEN)

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
			print "\n[*]TLS_FALLBACK_SCSV supported? ",
			print self._textColor("True", bcolors.OKGREEN) if self.TLS_FALLBACK_SCSV_SUPPORTED else self._textColor("False", bcolors.FAIL)
		#printing support for compression
		if self.COMPRESSION_ENABLED != None:
			print "\n[*]TLS COMPRESSION enabled? ",
			print self._textColor("False", bcolors.OKGREEN) if not self.COMPRESSION_ENABLED else self._textColor("True", bcolors.FAIL)
		#printing support for secure renegotiation extension
		if self.SECURE_RENEGOTIATION != None:
			print "\n[*]SECURE RENEGOTIATION supported?",
			print self._textColor("True", bcolors.OKGREEN) if self.SECURE_RENEGOTIATION else self._textColor("False", bcolors.FAIL)
		if self.tls_heartbeat != None:
			print "\n[*]TLS Heartbeat extension supported?",
			print "Yes" if self.tls_heartbeat else "No"
		#printing HSTS header info
		if self.hsts != None:
			self._print_hsts_results()
		#printing full support for sni
		if self.bad_sni_check != None:
			self._print_bad_sni_check()
		if self.tls_session_tickets != None:
			print "\n[*]TLS session tickets resumption? ",
			print self._textColor("YES", bcolors.OKGREEN) if self.tls_session_tickets else "NO"
		#ATTACKS
		print "\n\n################## ATTACKS #################"
		if self.scan_mode == TLSScanner.MODE.CIPHERS or self.scan_mode == TLSScanner.MODE.FULLSCAN:
			print "\n[*]POODLE attack (SSLv3): ",
			if self.poodle and not self.SECURE_RENEGOTIATION:
				print self._textColor("potentially vulnerable", bcolors.FAIL)
			else:
				print self._textColor("not vulnerable, SSLv3 disabled and/or TLS downgrade protection supported.", bcolors.OKGREEN)
			print "\n[*]BEAST attack? ",
			print self._textColor("NO", bcolors.OKGREEN) if not self.tls_beast else "not mitigated server side."
			print "\n[*]Heartbleed vulnerable?", 
			print self._textColor("YES, response written to file " + self.tls_heartbleed, bcolors.FAIL) if (type(self.tls_heartbleed) == str) else self._textColor("NO", bcolors.OKGREEN)
			print "\n[*]RC4 supported? ",
			print self._textColor("NO", bcolors.OKGREEN) if not self.rc4_enabled else self._textColor("YES", bcolors.FAIL)

		print "\n\n\n"

	#
	# Start a comprehensive scan of the given website.
	#
	def full_scan(self):
		self._scan_protocol_versions()
		self._scan_compression()
		self._scan_secure_renegotiation()
		self._scan_cipher_suite_accepted()
		
		self._check_bad_sni_response()
		self._check_heartbeat()
		self._check_session_ticket()
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
		#self.print_results()
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