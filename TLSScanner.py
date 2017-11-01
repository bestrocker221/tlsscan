import logging, datetime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socket, timeit
from colors import *
from concurrent.futures import ProcessPoolExecutor, as_completed,ThreadPoolExecutor
from time import sleep


def checkConnection(target):
		#test if target is reachable otherwise abort
		try:
			#socket.setdefaulttimeout(3)
			socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(target)
			return True
		except Exception as ex:
			print "\n" + str(ex)
			if ex.errno == 111:
				print "\nHost or port unavailable\n"
			return False

def TCPConnect(target):
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	try:
		sock.connect(target)
	except socket.error, msg:
		print "Couldnt connect with the socket-server: %s\n" % msg
		exit(1)
	return sock

##
# 
# Function that deliver ClientHello and return the server response
#
# parameters = ( target, cipher_code, TLSversion )
# 
# return (version, server_response) if accepted else None
# 
# #
def send_cipher_suite(parameters):
	target = parameters[0]
	cipher_code = parameters[1]
	#remove SCSV signaling suite
	if 0x5600 in cipher_code:
		cipher_code.remove(0x5600)
	ver = parameters[2]
	sock = TCPConnect(target)
	packet = TLSRecord(version="TLS_1_0")/\
			TLSHandshake()/\
			TLSClientHello(version=ver,
							compression_methods=0x00,
							cipher_suites=cipher_code,)
	sock.sendall(str(packet))
	try:
		resp = sock.recv(10240)
	except socket.error, msg:
		"socket error: " + msg

	sock.close()

	ssl_p = SSL(resp)
	
	if ssl_p.haslayer(TLSServerHello):
		return (ver,resp)
	else:
		return None

##
#
# Function for multiprocessing request to server
# 
# parameters = ( target, cipher_code_list, TLSversion )
# 
# return (version, server_response) if accepted else None
# 
# #
def order_cipher_suites(parameters):
	target = parameters[0]
	cipher_code_list = parameters[1]
	ver = parameters[2]
	ordered_cipher_list = {}
	ordered_cipher_list.update({ver:[]})
	go = True
	while go:
		resp = send_cipher_suite((target, cipher_code_list, ver))
		if resp != None:
			accepted_cipher = SSL(resp[1])
			accepted_cipher = accepted_cipher.getlayer(TLSServerHello).cipher_suite
			ordered_cipher_list.get(ver).append(accepted_cipher)
			cipher_code_list.remove(accepted_cipher)
		else:
			go = False
	return (ver,ordered_cipher_list)


class TLSScanner(object):

	def __init__(self, target):
		self.hostname = target[0]
		self.target = (socket.gethostbyname(self.hostname), target[1] )

		self.PROTOS = [p for p in TLS_VERSIONS.values() if p.startswith("TLS_") or p.startswith("SSL_")]
		self.PROTOS = sorted(self.PROTOS, reverse=True)
		
		self.cipher_suites_supported = []

		self.ACCEPTED_CIPHERS = {}
		self.ACCEPTED_ORDERED_CIPHERS = {}
		self.ACCEPTED_CIPHERS_LEN = 0
		self.TLS_FALLBACK_SCSV_SUPPORTED = None
		self.SECURE_RENEGOTIATION = None
		self.COMPRESSION_ENABLED = None
		self.RESPONSES = []
		self.SUPP_PROTO = []

		self.EVENTS = []

		if not checkConnection(self.target):
			sys.exit(1)
		print "TARGET: " + str(self.hostname) + " resolved to " + str(self.target[0]) +":"+ str(self.target[1])
		print "Date of the test: " + str(datetime.datetime.now())
		print "\n"

	def _scan_protocol_versions(self):
		print "scanning for supported protocol...  ",
		a = timeit.default_timer()
		for proto in self.PROTOS:
			vout,vin = ("SSL_3_0", proto)
			##Creating TLS packet
			sock = TCPConnect(self.target)

			packet = TLSRecord(version=vout)/\
				TLSHandshake()/\
				TLSClientHello(version=vin,
								compression_methods=0x00,
								cipher_suites=range(0x00, 0x4D)+range(0x60,0x70)
									+range(0x80,0xBA)+range(0xc001,0xc03c)+[0x5600],)
			sock.sendall(str(packet))
			try:
				resp = sock.recv(10240)
			except socket.error, msg:
				if msg.errno == 104:
					#tcp reset
				    pass	
				else:
					print "socket error: %s" % msg
				resp = ''

			sock.close()

			resp = SSL(resp)
			error = 0
			
			if resp.haslayer(TLSAlert):
				#print "Version: %d" % resp[TLSRecord].version
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

			if len(resp) == 0 or error != 0:
				self.RESPONSES.append("TLSRecord version: %s Handshake version: %s not supported" % (vout,vin))
			else:
				self.RESPONSES.append("TLSRecord version: %s Handshake version: %s supported" % (vout,vin))
				self.SUPP_PROTO.append(vin)

			if self.TLS_FALLBACK_SCSV_SUPPORTED == None:
				self.TLS_FALLBACK_SCSV_SUPPORTED = False

		self.SUPP_PROTO = sorted(self.SUPP_PROTO)
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)
		return

	def _scan_compression(self):
		print "scanning for compression support...  ",
		a = timeit.default_timer()
		ver = self.SUPP_PROTO[::-1][0]

		sock = TCPConnect(self.target)
		packet = TLSRecord(version=TLSVersion.TLS_1_0)/\
			TLSHandshake()/\
			TLSClientHello(version=ver,
					cipher_suites=range(0xfe)[::-1],
					compression_methods=range(1,0xff),)
		
		sock.sendall(str(packet))
		try:
			resp = sock.recv(10240)
		except socket.error, msg:
			print "socket error: %s" % msg
			return False
		
		sock.close()

		ssl_p = SSL(resp)
		if ssl_p.haslayer(TLSAlert):
			if ssl_p[TLSAlert].description == 50:
				#server does not support TLS compression
				#print "compression disabled"
				self.COMPRESSION_ENABLED = False
		elif ssl_p.haslayer(TLSServerHello):
			#print "server sent hello back --> compression enabled"
			self.COMPRESSION_ENABLED = True
		print "\t\t\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	def _scan_secure_renegotiation(self):
		print "scanning for secure renegotiation extension..  ",
		a = timeit.default_timer()
		ver = self.SUPP_PROTO[::-1][0]

		sock = TCPConnect(self.target)
		packet = TLSRecord(version="TLS_1_0")/\
				TLSHandshake()/\
				TLSClientHello(version=ver,
								compression_methods=0x00,
								cipher_suites=range(0xff),
								extensions=TLSExtension()/
											TLSExtRenegotiationInfo(),)
		sock.sendall(str(packet))
		try:
			resp = sock.recv(10240)
		except socket.error, msg:
			"socket error: " + msg

		sock.close()

		ssl_p = SSL(resp)
		if ssl_p.haslayer(TLSExtRenegotiationInfo):
			#ssl_p.getlayer(TLSExtRenegotiationInfo).show()
			self.SECURE_RENEGOTIATION = True
		else:
			self.SECURE_RENEGOTIATION = False
		print "\tdone. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	
	#def _scan_accepted_ciphers(self):
	#	if len(self.SUPP_PROTO) == 0:
	#		self._scan_protocol_versions()
	#	print "scanning ciphers..",
	#	a = timeit.default_timer()
	#	parameters = []
	#	for protocol in self.SUPP_PROTO:
	#		for cipher_suite in TLS_CIPHER_SUITES:
	#			parameters.append((self.target,cipher_suite,protocol))
#
#		with ProcessPoolExecutor(max_workers=10) as executor:
#			for result in executor.map(send_cipher_suite, parameters):
#				if result != None:
#					accepted_cipher = SSL(result[1])
#					accepted_cipher = accepted_cipher.getlayer(TLSServerHello).cipher_suite
#					
#					if self.ACCEPTED_CIPHERS.has_key(result[0]):
#						self.ACCEPTED_CIPHERS.get(result[0]).append(accepted_cipher)
#					else:
#						to_add = {result[0]:[accepted_cipher]}
#						self.ACCEPTED_CIPHERS.update(to_add)
#
#		for i in self.ACCEPTED_CIPHERS.keys():
#			self.ACCEPTED_CIPHERS_LEN += len(self.ACCEPTED_CIPHERS[i])
#
#		print "\t\t\t\t\tdone. ", 
#		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)
#		self._order_cipher_suite_accepted()

	
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
			parameters.append((self.target, cipher_scan_list[proto], proto))

		with ProcessPoolExecutor(max_workers=len(self.SUPP_PROTO)) as executor:
			for ordered_cipher_list in executor.map(order_cipher_suites, parameters):
				self.ACCEPTED_ORDERED_CIPHERS.update(ordered_cipher_list[1])
				self.ACCEPTED_CIPHERS_LEN += len(ordered_cipher_list[1][ordered_cipher_list[0]])
		print "done. ",
		print "in --- %0.4f seconds ---" % float(timeit.default_timer()-a)

	#
	# Printing result of the test.
	#
	def _printResults(self):
		print "\n"
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

		for proto in self.ACCEPTED_ORDERED_CIPHERS.keys():
			print "\n" + str(proto) + " supports " + str(len(self.ACCEPTED_ORDERED_CIPHERS[proto])) + " cipher suites.\n"
			for cipher in self.ACCEPTED_ORDERED_CIPHERS[proto]:
				print "Protocol: %s -> %s supported." % (proto,TLS_CIPHER_SUITES[cipher])

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
