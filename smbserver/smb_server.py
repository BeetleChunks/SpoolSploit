import hashlib

from random import choice
from string import ascii_uppercase, digits

from impacket import smbserver, version
from impacket.ntlm import compute_lmhash, compute_nthash

class SmbServer:
	def __init__(self, config):
		self._smb_conf = config

		# Defaults
		self.lhost = "0.0.0.0"
		self.lport = 445

	def start_server(self):
		self.server = smbserver.SimpleSMBServer(
				listenAddress=self.lhost, listenPort=self.lport,
				configFile=self._smb_conf)

		self.server.start()

def main():
	smb_conf = "./smb-v1.conf"
	smb_srv  = SmbServer(smb_conf)

	smb_srv.start_server()

if __name__ == '__main__':
	main()