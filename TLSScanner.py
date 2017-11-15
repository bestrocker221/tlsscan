import socks, logging, datetime, socket, timeit, collections, requests
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
	from scapy.all import TLS
	from scapy.all import *
except ImportError:
	from scapy_ssl_tls.ssl_tls import *
from colors import *
from time import sleep
from concurrent.futures import ProcessPoolExecutor
from asn1crypto.x509 import Certificate

#
# Test if target is reachable otherwise abort
#
def checkConnection(target):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(target)
		return True
	except socket.error as ex:
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
# Function for receiving all data in the stream.
#
def recvall(sock, buf_size=1024):
	buf = []
	sock.settimeout(1)
	while True:
		try:
			chunk = sock.recv(buf_size)
			if len(chunk) == 0:
				break
			buf.append(chunk)
		except socket.error as msg:
				break
	return b''.join(buf)


# 
# Function that deliver ClientHello and return the server response if any
# return (version, server_response) if accepted else None
# 
def send_client_hello(tls_scan_obj):

	compression = range(1,0xff) if tls_scan_obj.tls_compression else 0x00

	sock = TCPConnect(tls_scan_obj.target)
	packet = TLSRecord(version=tls_scan_obj.version)/\
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
		ocsp = TLSExtension(type="status_request", length=5)
		ocsp = str(ocsp).encode("hex") + "0100000000" #adding ocsp request manually
		ocsp = ocsp.decode("hex")
		packet.getlayer(TLSClientHello).extensions.append(SSL(ocsp))
	if tls_scan_obj.session_ticket:
		packet.getlayer(TLSClientHello).extensions.append(TLSExtension()/TLSExtSessionTicketTLS())

	sleep(float(tls_scan_obj.time_to_wait)/1000)
	sock.sendall(str(packet))
	
	resp = recvall(sock)

	if tls_scan_obj.tls_heartbleed:
		p = TLSRecord(version=tls_scan_obj.version)/TLSHeartBeat(length=2**14-1,data='bleeding...')
		sock.settimeout(1)
		sock.sendall(str(p))
		try:
			resp2 = sock.recv(8192)
		except (socket.timeout, socket.error) as msg:
			return (tls_scan_obj.version, str(msg))	
		sock.close()
		return (tls_scan_obj.version, resp2)

	sock.close()
	ssl_p = SSL(resp)
	if ssl_p.haslayer(TLSServerHello) or ssl_p.haslayer(TLSAlert) or ssl_p.haslayer(TLSCertificate):
		return (tls_scan_obj.version,resp)
	else:
		return None


#
# Function for multiprocessing requests to server
# 
# parameters = ( tls_scan_obj )
# 
# return (version, ordered_cipher_list)
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
	def __init__(self, target, server_name, cipher_list= [], version="TLS_1_1", tls_fallback=False, ocsp=False,
					tls_compression=False, tls_sec_reneg=False, tls_heartbeat=False, tls_heartbleed=False,
					session_ticket=False, time_to_wait=0):
		self.target = target
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
		self.cipher_list = TLS_CIPHER_SUITES.keys()[:]
		if not self.tls_fallback:
			self.cipher_list.remove(0x5600) #removing scsv signaling suite
		
class TLSScanner(object):
	class MODE:
		FULLSCAN = "FULLSCAN",
		CERTSCAN = "CERTSCAN",
		SUPPROTO = "SUPPROTO",
		CIPHERS  = "CIPHERS"

	def __init__(self, target, time_delay, verbose, to_file, torify):
		self._hostname = target[0]
		self._port = target[1]
		self._verbose = verbose
		self._to_file = to_file
		self._time_delay = time_delay #timing variable for requests
		self._requests_session = requests.session()
		self._torify = torify
		if self._torify:
			self._set_tor_proxy()
		self.target = self._make_target()
		self._scan_mode = None
		
		self._PROTOS = sorted([p for p in TLS_VERSIONS.values() if p.startswith("TLS_") or p.startswith("SSL_")], reverse=True)
		
		self._server_certificate = None
		self._certificate_chain = []
		# Structure of _accepted_ordered_ciphers:
		# Example
		# { "TLS_1_0": [0x00,0x01], "TLS_1_1":[0x32], ...}
		# { proto: [supp_ciphers], ... }
		self._accepted_ordered_ciphers = {}
		self._accepted_ciphers_length = 0

		self._tls_fallback_scsv = None
		self._secure_renegotiation = None
		self._compression_enabled = None
		self._tls_heartbeat = None
		self._tls_heartbleed = None
		self._tls_session_tickets = None
		self._tls_ocsp_stapling = None

		self._tls_beast = False
		self._rc4_enabled = False
		self._poodle = False
		self._export_ciphers = False

		self._bad_sni_check = None
		self._hsts = None
		self._http_response = None

		self._SUPP_PROTO = []  #list of ssl/tls supported protocol by the server

		# Structure of events:
		# Event() list
		self._EVENTS = []
		
		if not checkConnection((self._hostname, self._port)):
			sys.exit(1)

		print "TARGET: " + str(self._hostname) + " resolved to " + str(self.target[0]) +":"+ str(self._port)
		print "Date of the test: " + str(datetime.datetime.now())
		if self._time_delay > 0:
			print "Timing: %d millisec between each request." % self._time_delay
		print "\n"
	
	def _make_target(self):
		try:
			return (socket.gethostbyname(self._hostname) if not self._torify else self._hostname, self._port)
		except socket.gaierror as err:
			if err.errno == -2:
				print "Host does not resolve to a valid IP\nPlease try again with a correct hostname\n\n"
			else:
				print err
			exit(1)

	def _set_tor_proxy(self):
		print "Checking tor proxy connectivity...   "
		if not checkConnection(("127.0.0.1", 9050)):	#assuming a local TOR proxy
			print "TOR PROXY NOT RUNNING\n"
			exit(1)
		else:
			socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
			print "TOR PROXY RUNNING ON PORT 9050\n"
			socket.socket = socks.socksocket	#setting global socket setting to use socks.socksocket
			self._requests_session.proxies = {
				'http':'socks5h://127.0.0.1:9050',	#socks5h for forcing DNS resolution through proxy
				'https':'socks5h://127.0.0.1:9050'
			}
			url = "https://icanhazip.com"	#url to get ext ip
			response = self._requests_session.get(url)
			print "TOR IP: ", response.text

	#
	# Colorize text output if written to terminal, not to file.
	#
	def _textColor(self, txt, color):
		return txt if self._to_file else textColor(txt,color)

	#
	# Check for TLS session ticket extension support
	#
	def _check_session_ticket(self):
		if len(self._SUPP_PROTO) == 0:
			self._scan_protocol_versions()
		print "checking TLS session ticket support..",
		ver = self._SUPP_PROTO[0]
		a = timeit.default_timer()
		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self._hostname, session_ticket=True)
		ver, resp = send_client_hello(tls_scan_obj)
		resp = SSL(resp)
		self._tls_session_tickets = False
		for ext in resp.getlayer(TLSServerHello).extensions:
			if ext.type == 35:
				#session ticket supported
				self._tls_session_tickets = True
		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Check for OCSP request extension support.
	#
	def _check_ocsp(self):
		print "checking ocsp response..             ",
		if len(self._SUPP_PROTO) == 0:
			self._scan_protocol_versions()
		ver = self._SUPP_PROTO[0]
		a = timeit.default_timer()
		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self._hostname, ocsp=True)
		ver, resp = send_client_hello(tls_scan_obj)
		resp = SSL(resp)
		server_hello = resp.getlayer(TLSServerHello)
		self._tls_ocsp_stapling = False
		for ext in server_hello.extensions:
			if ext.type ==0x0005:
				self._tls_ocsp_stapling = True
		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Check for TLS heartbeat extension support.
	#
	def _check_heartbeat(self):
		if len(self._SUPP_PROTO) == 0:
			self._scan_protocol_versions()
			if "TLS_1_1" not in self._SUPP_PROTO or "TLS_1_2" not in self._SUPP_PROTO:
				self._tls_heartbeat = False
				return
		print "checking TLS heartbeat extension...  ",
		ver = self._SUPP_PROTO[0]
		a = timeit.default_timer()

		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self._hostname, tls_heartbeat=True)
		ver, resp = send_client_hello(tls_scan_obj)
		self.tls_heartbeat = False
		if resp != None:
			resp = SSL(resp)
			self._tls_heartbeat = True if resp.haslayer(TLSExtHeartbeat) else False
		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)
		if self._tls_heartbeat:
			self._check_heartbleed()
		else:
			self._tls_heartbleed = False

	#
	# Check for heartbleed vulnerability.
	#
	def _check_heartbleed(self):
		print "checking TLS heartbleed...           ", 
		ver = self._SUPP_PROTO[0]
		a = timeit.default_timer()
		tls_scan_obj = TLSScanObject(target=self.target, version=ver, server_name=self._hostname, tls_heartbleed=True)
		resp = send_client_hello(tls_scan_obj)
		self._tls_heartbleed = False		
		if resp != None:
			resp = resp[1]
			if len(resp) == 0:
				#print "nothing returned"
				pass
			elif resp == str(104):
				#print "connection reset by peer"
				pass
			elif resp == "timed out":
				#connection timed out, probably not vulnerable
				pass
			elif SSL(resp[1]).haslayer(TLSAlert):
				if SSL(resp[1]).getlayer(TLSAlert).description == 10:
					pass
					#unexpected msg
			else:
				with file("bleed_" + self._hostname + ".txt", "w") as f:
					f.write(repr(resp))
				self._tls_heartbleed = "bleed_" + self._hostname + ".txt"

		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Analyze certificates of the server.
	#
	def _analyze_certificates(self):
		if len(self._SUPP_PROTO) == 0:
			self._scan_protocol_versions()
		if self._server_certificate == None:
			print "certificate is missing. Error, try again"
			sys.exit(1)
	#
	# Save certificate chain from the server.
	#
	def _save_cert_chain(self, TLSCertificateList):
		print "loading certificate chain...         ",
		a = timeit.default_timer()

		for cert in TLSCertificateList.certificates:
			c = Certificate.load(bytes(cert.data))
			self._certificate_chain.append(c)
		
		self._server_certificate = self._certificate_chain[0]
		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Try to send different Server Name Indication.
	#
	def _check_bad_sni_response(self):
		print "checking bad sni response...         ",
		a = timeit.default_timer()
		bogus_hostname = "wzw.bogus-address.cmx"

		ver = self._SUPP_PROTO[0]
		tls_scan_obj = TLSScanObject(target=self.target, server_name=bogus_hostname, version=ver)
		resp = send_client_hello(tls_scan_obj)
		if resp != None:
			resp = SSL(resp[1])
			if resp.haslayer(TLSCertificate):
				cert = Certificate.load(bytes(resp.getlayer(TLSCertificate).data))
				cert_hostnames = cert.valid_domains
				#very basic check on hostname match, if server returns incorrect certificate it will however accept the connection
				self._bad_sni_check = bogus_hostname in cert_hostnames
		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Scan ssl/tls server version support and save certificates retrieved.
	#
	def _scan_protocol_versions(self):
		print "scanning for supported protocol...  ",
		a = timeit.default_timer()
		cert_list = None
		for proto in self._PROTOS:
			error = 0
			#scan for accepted protocol and include SCSV fallback signal
			tls_scan_obj = TLSScanObject(target=self.target, server_name=self._hostname, version=proto,
											tls_fallback=True, time_to_wait=self._time_delay)
			resp = send_client_hello(tls_scan_obj)
			if resp == None:
				error = 1
			else:
				resp = SSL(resp[1])
				if resp.haslayer(TLSAlert):
					if resp[TLSAlert].description == 86:
						#signaling suite supported
						#print "INAPPROPRIATE_FALLBACK --> SERVER SUPPORT SCSV SIGNALING"
						self._tls_fallback_scsv = True
					if resp[TLSAlert].description == 70:
						#Protocol not supported by server
						error = 1
					if resp[TLSAlert].description == 40:
						#Handshake failure
						error = 1
				elif resp.haslayer(TLSCertificateList) and cert_list == None:
					cert_list = resp.getlayer(TLSCertificateList)
			if error != 0:
				self._EVENTS.append(Event(proto+"_SUPPORT", Event.LEVEL.WHITE, "TLSRecord version: TLS_1_0 Handshake version: %s not supported" % proto))
			else:
				self._EVENTS.append(Event(proto+"_SUPPORT", Event.LEVEL.WHITE, "TLSRecord version: TLS_1_0 Handshake version: %s supported" % proto))
				self._SUPP_PROTO.append(proto)
		if self._tls_fallback_scsv == None:
			self._tls_fallback_scsv = False

		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)
		if cert_list != None:
			self._save_cert_chain(cert_list)
		else:
			print "error.. server didnt send certificate"
			exit(1)

	#
	# Scan the server for TLS compression support.
	#
	def _scan_compression(self):
		print "scanning for compression support...  ",
		a = timeit.default_timer()
		ver = self._SUPP_PROTO[0]

		#scan if compression is enabled (scan for every protocol?)
		tls_scan_obj = TLSScanObject(target=self.target, server_name=self._hostname, version=ver, tls_compression=True,
										time_to_wait=self._time_delay)
		resp = send_client_hello(tls_scan_obj)
		self._compression_enabled = False
		if resp != None:
			resp = SSL(resp[1])
			if resp.haslayer(TLSAlert):
				if resp[TLSAlert].description == 50:
					#server does not support TLS compression
					self._compression_enabled = False
			elif resp.haslayer(TLSServerHello):
				#print "server sent hello back --> compression enabled"
				if resp.getlayer(TLSServerHello).compression_method != 0:
					self._compression_enabled = True
		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Scan the server for secure renegotiation support.
	#
	def _scan_secure_renegotiation(self):
		print "scanning for secure renegotiation extension..  ",
		a = timeit.default_timer()
		ver = self._SUPP_PROTO[0]
		tls_scan_obj = TLSScanObject(target=self.target, server_name=self._hostname, version=ver, tls_sec_reneg=True,
										time_to_wait=self._time_delay)
		resp = send_client_hello(tls_scan_obj)
		self._secure_renegotiation = False
		if resp != None:
			resp = SSL(resp[1])
			self._secure_renegotiation = True if resp.haslayer(TLSExtRenegotiationInfo) else False
		print "\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)
	
	#
	# Analize ciphers accepted by the server and point out what's bad.
	#
	def _find_bad_ciphers(self, version, cipher_list):
		event_list = []
		for cipher in cipher_list:
			if TLS_CIPHER_SUITES[cipher].endswith("MD5"):
				if Event.CODE.MD5 not in event_list:
					event_list.append(Event.CODE.MD5)
					self._EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "cipher (%s): MD5 is deprecated and considered insecure" % cipher))
			if TLS_CIPHER_SUITES[cipher].endswith("SHA"):
				if Event.CODE.SHA not in event_list:
					event_list.append(Event.CODE.SHA)
					self._EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.YELLOW, "SHA could be upgraded to SHA-2 (even though used in case does not pose a real threat) "))
			if "_CBC_" in TLS_CIPHER_SUITES[cipher] and version == "SSL_3_0":
				if Event.CODE.POODLE not in event_list:
					event_list.append(Event.CODE.POODLE)
					self._EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "CBC and SSL_3 are vulnerable to POODLE attack!"))
					self._poodle = True
			if "_CBC_" in TLS_CIPHER_SUITES[cipher] and (version == "TLS_1_0" or version == "SSL_3_0"):
				if Event.CODE.BEAST not in event_list:
					event_list.append(Event.CODE.BEAST)
					self._EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.WHITE, version + " and CBC could lead to BEAST attack! (if not client mitigated)"))
					self._tls_beast = True
			if "RC4" in TLS_CIPHER_SUITES[cipher]:
				if Event.CODE.RC4 not in event_list:
					event_list.append(Event.CODE.RC4)
					self._EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "RC4 in known to be insecure and deprecated"))
					self._rc4_enabled = True
			if "DES" in TLS_CIPHER_SUITES[cipher]:
				if Event.CODE.DES not in event_list:
					event_list.append(Event.CODE.DES)
					self._EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.YELLOW, "DES/3DES considered weak, could disable."))
			if "EXPORT" in TLS_CIPHER_SUITES[cipher]:
				if Event.CODE.EXPORT not in event_list:
					event_list.append(Event.CODE.EXPORT)
					self._EVENTS.append(Event(version + "_CIPHERS", Event.LEVEL.RED, "EXPORT ciphers could lead to Logjam and FREAK"))
					self._export_ciphers = True
			#TODO
			#
			#
			#
	#
	# Scan cipher suites accepted and ordered by server preference.
	#
	def _scan_cipher_suite_accepted(self):
		if len(self._SUPP_PROTO) == 0:
			self._scan_protocol_versions()
		print "ordering cipher suites based on server preference...   ",
		a = timeit.default_timer()
		cipher_scan_list = {}
		for proto in self._SUPP_PROTO:
			cipher_scan_list.update({proto:TLS_CIPHER_SUITES.keys()})
		parameters = []
		for proto in cipher_scan_list.keys():
			parameters.append(TLSScanObject(target=self.target, server_name=self._hostname, version=proto,
											cipher_list=cipher_scan_list[proto], time_to_wait=self._time_delay))
		with ProcessPoolExecutor(max_workers=len(self._SUPP_PROTO)) as executor:
			for version, ordered_cipher_list in executor.map(order_cipher_suites, parameters):
				self._accepted_ordered_ciphers.update(ordered_cipher_list)
				self._find_bad_ciphers(version,ordered_cipher_list[version])
				self._accepted_ciphers_length += len(ordered_cipher_list[version])
		print "done. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Make a HEAD request to the server (https) and analyze headers returned.
	# Look for HTTP Strict Transport Security header
	#
	def _check_hsts(self):
		print "looking for HSTS header...           ",
		a = timeit.default_timer()
		headers = {
    		'cache-control': "no-cache"
		}
		url = "https://" + self._hostname
		#disabling warning, we want just to know if hsts is supported, even though the server certificate security is broken.
		requests.urllib3.disable_warnings()
		#disabling certificate verification
		response = self._requests_session.head(url, headers=headers, verify=False)
		self._hsts = response.headers["Strict-Transport-Security"] if ("Strict-Transport-Security" in response.headers.keys()) else False
		self._http_response = response
		print "\t\t\tdone. in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Print certificate information.
	#
	def _print_certificate_info(self, certificate):
		tbs_cert = certificate.native["tbs_certificate"]
		print "\n################# CERTIFICATE INFORMATION for %s #################\n" % tbs_cert["subject"]["common_name"]
		
		print "Signature Algorithm:\t",
		signature = tbs_cert["signature"]["algorithm"].lower()
		if "sha1" in signature or "md5" in signature:
			print self._textColor(signature + " INSECURE", bcolors.FAIL)
		else:
			print self._textColor(signature, bcolors.OKGREEN)
		if self._verbose:
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
			if (self._hostname in tbs_cert["subject"]["common_name"] or self._hostname in certificate.valid_domains):
				print self._textColor("YES", bcolors.OKGREEN) 
			else:
				print self._textColor("NO", bcolors.FAIL)
		print "(Requested) ", self._hostname, " (Certificate)",tbs_cert["subject"]["common_name"]
		if not certificate.ca:
			print "[*]Hostname matches with alternative name: ",
			if (self._hostname in certificate.valid_domains):
				print self._textColor(self._hostname, bcolors.OKGREEN)
			else:
				print self._textColor("Nothing", bcolors.FAIL)
		print "[*]Is a CA certificate?",
		print "YES" if certificate.ca else "NO"
		print "[*]Is a self-signed certificate? ", certificate.self_signed.upper()
		
		if self._verbose:
			print "[*]CRL url: ", certificate.crl_distribution_points[0].url if (len(certificate.crl_distribution_points) > 0) else "NO CLR"
			print "[*]OSCP url: ",certificate.ocsp_urls[0] if (len(certificate.ocsp_urls)>0) else "NO OCSP" 
			print "[*]Valid domains for certificate: ", certificate.valid_domains if (len(certificate.valid_domains) > 0) else "None"

	#
	# Prints supported protocols.
	#
	def _print_supproto(self):
		print "\n################# PROTOCOLS SUPPORTED #################\n"
		print "SUPPORTED PROTOCOLS FOR HANDSHAKE: ",
		for i in self._SUPP_PROTO:
			if i=="SSL_3_0" or i=="SSL_2_0":
				print self._textColor(i, bcolors.FAIL),
			elif i=="TLS_1_0":
				print self._textColor(i, bcolors.WARNING),
			else:
				print self._textColor(i, bcolors.OKGREEN),

	#
	# Prints cipher suites accepted.
	# 
	def _print_ciphers(self):
		print "\n\n################## CIPHER SUITES #################"
		if self._accepted_ciphers_length > 0:
			print "\n\nAccepted cipher-suites (",
			print self._textColor(str(self._accepted_ciphers_length), bcolors.OKGREEN),
			print "/ %d ) Ordered by server preference." %(len(TLS_CIPHER_SUITES))

			for proto in self._accepted_ordered_ciphers.keys():
				print "\n" + str(proto) + " supports " + str(len(self._accepted_ordered_ciphers[proto])) + " cipher suites.\n"
				for cipher in self._accepted_ordered_ciphers[proto]:
					print "Protocol: %s -> %s (%s) supported." % (proto,TLS_CIPHER_SUITES[cipher], hex(cipher)),
					print self._textColor("FS", bcolors.OKGREEN) if "RSA" not in TLS_CIPHER_SUITES[cipher].split("_")[0] else self._textColor("non FS", bcolors.FAIL)
				for ev in self._EVENTS:
					if ev.subject == (proto+"_CIPHERS"):
						print self._textColor("[*]ALERT: ", bcolors.FAIL),
						print self._textColor(ev.description, bcolors.FAIL) if ev.level == Event.LEVEL.RED else self._textColor(ev.description, bcolors.WARNING)
		print "\n\tFS = Forward Secrecy (should use only cipher suite with it)"

	#
	# Printing result of the test.
	#
	def print_results(self):
		print "\n###########  PRINTING RESULTS  ###########\n"
		
		for ev in self._EVENTS:
			if "SUPPORT" in ev.subject:
				print "[*]INFO: ", ev.description

		#printing certificate informations
		print "\nTotal number of certificates received: ", len(self._certificate_chain)
		for cert in self._certificate_chain:
			self._print_certificate_info(cert)
		
		#printing supported protocols
		self._print_supproto()

		#printing cipher suites accepted
		#TODO make prints based on mode
		if self._scan_mode == TLSScanner.MODE.CIPHERS or self._scan_mode == TLSScanner.MODE.FULLSCAN:
			self._print_ciphers()
		
		print "\n\n################## SECURITY OPTIONS #################"
		#printing support for SCSV
		if self._tls_fallback_scsv != None:
			print "\n[*]TLS_FALLBACK_SCSV supported? ",
			print self._textColor("True", bcolors.OKGREEN) if self._tls_fallback_scsv else self._textColor("False", bcolors.FAIL)
		#printing support for compression
		if self._compression_enabled != None:
			print "\n[*]TLS COMPRESSION enabled? ",
			print self._textColor("False", bcolors.OKGREEN) if not self._compression_enabled else self._textColor("True", bcolors.FAIL)
		#printing support for secure renegotiation extension
		if self._secure_renegotiation != None:
			print "\n[*]SECURE RENEGOTIATION supported?",
			print self._textColor("True", bcolors.OKGREEN) if self._secure_renegotiation else self._textColor("False", bcolors.FAIL)
		if self._tls_heartbeat != None:
			print "\n[*]TLS Heartbeat extension supported?",
			print "Yes" if self._tls_heartbeat else "No"
		if self._tls_ocsp_stapling != None:
			print "\n[*]OCSP stapling supported?",
			print self._textColor("Yes",bcolors.OKGREEN) if self._tls_ocsp_stapling else self._textColor("No", bcolors.WARNING)
		#printing HSTS header info
		if self._hsts != None:
			print "\n[*]HTTP Strict Transport Security enabled on https://%s ? " % self._hostname ,
			if self._hsts:
				print self._textColor("YES", bcolors.OKGREEN)
				print "\tHeader: ", self._textColor(self._hsts, bcolors.OKGREEN)
				print "\tInclude subdomains? ", self._textColor("YES", bcolors.OKGREEN) if ("includesubdomains" in self._hsts.lower()) else self._textColor("NO", bcolors.FAIL)
				print "\tPreloaded? ", self._textColor("YES", bcolors.OKGREEN) if ("preload" in self._hsts.lower()) else self._textColor("NO", bcolors.FAIL)
			else:
				print self._textColor("NO", bcolors.FAIL)
			if "Location" in self._http_response.headers.keys():
				print "\tServer returned redirect header to: ", self._http_response.headers["location"]
		#printing full support for sni
		if self._bad_sni_check != None:
			print "\n[*]Incorrect Server Name Indication alert? ",
			print "NO" if not self._bad_sni_check else self._textColor("YES", bcolors.OKGREEN)
		if self._tls_session_tickets != None:
			print "\n[*]TLS session tickets resumption? ",
			print self._textColor("YES", bcolors.OKGREEN) if self._tls_session_tickets else "NO"
		#ATTACKS
		print "\n\n################## ATTACKS #################"
		if self._scan_mode == TLSScanner.MODE.CIPHERS or self._scan_mode == TLSScanner.MODE.FULLSCAN:
			print "\n[*]POODLE attack (SSLv3): ",
			if self._poodle and not self._secure_renegotiation:
				print self._textColor("potentially vulnerable", bcolors.FAIL)
			else:
				print self._textColor("not vulnerable, SSLv3 disabled and/or TLS downgrade protection supported.", bcolors.OKGREEN)
			print "\n[*]BEAST attack? ",
			print self._textColor("NO", bcolors.OKGREEN) if not self._tls_beast else "not mitigated server side."
			print "\n[*]EXPORT ciphers enabled? ",
			print self._textColor("NO", bcolors.OKGREEN) if not self._export_ciphers else self._textColor("YES",bcolors.RED)
			if self._tls_heartbleed != None:
				print "\n[*]Heartbleed vulnerable?", 
				print self._textColor("YES, response written to file " + self._tls_heartbleed, bcolors.FAIL) if (type(self._tls_heartbleed) == str) else self._textColor("NO", bcolors.OKGREEN)
			print "\n[*]RC4 supported? ",
			print self._textColor("NO", bcolors.OKGREEN) if not self._rc4_enabled else self._textColor("YES", bcolors.FAIL)

		print "\n\n################## MISC ##################"
		print "\nRequest to %s \nStatus code: %s %s" % (self._http_response.url, self._http_response.status_code, self._http_response.reason)
		
		print "\n\n\n"

	#
	# Start a comprehensive scan of the given website.
	#
	def full_scan(self):
		self._scan_protocol_versions()
		self._scan_compression()
		self._scan_secure_renegotiation()
		self._scan_cipher_suite_accepted()
		self._check_ocsp()
		self._check_bad_sni_response()
		self._check_heartbeat()
		self._check_session_ticket()
		self._check_hsts()

	def scan(self, mode):
		print "\nStarting SSL/TLS test on %s --> %s:%d" % (self._hostname,self.target[0],self.target[1])
		print "TYPE SCAN:  %s\n\n" % mode
		self._scan_mode = mode
		if mode == TLSScanner.MODE.FULLSCAN:
			self.full_scan()
		elif mode == TLSScanner.MODE.CIPHERS:
			self._scan_cipher_suite_accepted()
		elif mode == TLSScanner.MODE.SUPPROTO:
			self._scan_protocol_versions()
		elif mode == TLSScanner.MODE.CERTSCAN:
			self._analyze_certificates()
		self.print_results()
		print "\n ---------- SCAN FINISHED ----------\n"
