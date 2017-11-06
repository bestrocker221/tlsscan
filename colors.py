
class bcolors:
    HEADER = '\033[95m'     #purple
    OKBLUE = '\033[94m'     #blue
    OKGREEN = '\033[92m'    #green
    WARNING = '\033[93m'    #orange
    FAIL = '\033[91m' 		#red
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[31m'
    UNDERLINE = '\033[4m'

def printGreen(txt):
	print bcolors.OKGREEN + txt + bcolors.ENDC,
def printRed(txt):
	print bcolors.RED + txt + bcolors.ENDC,
def printOrange(txt):
    print bcolors.FAIL + txt + bcolors.ENDC,
def printWarning(txt):
	print bcolors.WARNING + txt + bcolors.ENDC,
def printBlue(txt):
	print bcolors.OKBLUE + txt + bcolors.ENDC,
def printHeader(txt):
	print bcolors.HEADER+ txt + bcolors.ENDC,

def textColor(txt, color):
    return color + txt + bcolors.ENDC