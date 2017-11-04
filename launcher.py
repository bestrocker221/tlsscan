import sys, datetime, argparse, timeit, signal, os
from TLSScanner import TLSScanner
from  multiprocessing import Process
from scapy.all import *

parser = argparse.ArgumentParser(usage= sys.argv[0]+ ' <website> [options]', 
	description='SSL/TLS website passive analyzer.',
	epilog='''
...             likewise for this epilog whose whitespace will
...         be cleaned up and whose words will be wrapped
...         across a couple lines
''')


parser.add_argument('website',  type=str, action='store', help='website to scan.')
parser.add_argument('-p', '--port',  type=int, action='store',default=443, help='TCP port to test (default: 443).')
parser.add_argument('--fullscan', action='store_true', help='start a full scan of the website.')
parser.add_argument('--ciphers', action='store_true', help='start a scan of server supported cipher suites.')
parser.add_argument('--suppproto', action='store_true', help='perform only a scan of supported protocols version.')
parser.add_argument('--certscan', action='store_true', help='perform only a scan of the server certificate.')
parser.add_argument('-d', '--delay', type=int, action='store', default=0, help="wait N milliseconds between each request.")
parser.add_argument('-vv', '--verbose', action='store_true', default=False, help="show verbose information.")
parser.add_argument('-w', '--write',  action='store',
	#default="output_"+str(datetime.datetime.now()).replace(" ","_")+".txt", 
	help='insert filename to write test output.')
parser.add_argument('-s', '--sniff', action='store_true',
	 #default="pcap_"+str(datetime.datetime.now()).replace(" ","_")+".pcap",
	 help='save full packet capture in .pcap format. (NEED SUDO PRIVILEGES)')
parser.add_argument('-t', '--torify', action='store_true', help='make the script running under Tor network.')
parser.add_argument('-i', '--input',  type=argparse.FileType('r'), action='store', help='input file with website list (\\n separated.')
parser.add_argument('-v', '--version', action='version', version='version 1.0', help='show program version.')


def main():
	#parser.print_help()
	args = parser.parse_args()
	#print args.input.read()
	
	if args.write:
		sys.stdout = open(args.write, 'w')
	
	print "\033c"
	printScreen()

	target = (args.website, int(args.port))

	#print args.website, args.port, args.fullscan, args.write, args.torify
	start_time = timeit.default_timer()
	print args
	print "\n"

	scanner = TLSScanner(target=target, time_delay=args.delay, verbose=args.verbose)

	sniffer_process = None
	if args.sniff:
		if os.geteuid() != 0:
			exit("You need to have root privileges to run SNIFFING mode.\nExiting.")

		filename = args.write + ".pcap" if args.write else "pcap_"+str(datetime.datetime.now()).replace(" ","_")+".pcap"
		sniffer_process = Process(target=sniffer, args=(filename, scanner.target[0]))
		sniffer_process.start()

	if args.ciphers:
		scanner._order_cipher_suite_accepted()
		scanner._printResults()
	elif args.certscan:
		scanner._analyze_certificate()
		scanner._printResults()
	elif args.suppproto:
		scanner._scan_protocol_versions()
		scanner._printResults()
	if args.fullscan:
		scanner._fullScan()
		#scanner._scan_protocol_versions()
		scanner._printResults()

	if sniffer_process != None:
		sniffer_process.terminate() 
	print "Finished in --- %s seconds ---\n\n" % (timeit.default_timer()-start_time)

def signal_handler(signal, frame):
    raise KeyboardInterrupt

def sniffer(filename, ip):
	filter = "host " + str(ip)
	signal.signal(signal.SIGTERM, signal_handler)
	wrpcap(filename, sniff(filter=filter))

def printScreen():
	print(
'''
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
|                                             |
|   ############  ###         #############   |
|   ############  ###         #############   | Scan a website and analyze 
|       ###       ###         ###             | HTTPS configurations and 
|       ###       ###         #############   | certificates.
|       ###       ###         #############   |
|       ###       ###                   ###   |
|       ###       ###                   ###   | Find misconfigurations
|       ###       ##########  #############   | which could lead to 
|       ###       ##########  #############   | potential attacks.
|                                             |
| and SSL for HTTPS  Passive Security Scanner |
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
''')


if __name__ == '__main__':
	main()