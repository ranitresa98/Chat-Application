import random
from security import Diffie_Hellman
import hashlib

class user_client:
	roll_no=2020202019
	def __init__(self,username):

		self.username=username      #name appended wih roll no. so username will be unique for every user
		self.private_key=self.get_privatekey()
		self.imd_key=Diffie_Hellman(self.private_key).intermediate_key
		self.groups={}


	def get_privatekey(self):
		pri_key=random.getrandbits(192)
		pri_key+=self.roll_no
		pri_key=str(pri_key)
		pri_key=hashlib.sha256(pri_key.encode())
		pri_key=pri_key.hexdigest()		
		pri_key=pri_key[:11]
		pri_key=int(pri_key,16)
		return pri_key

	def joingroup(self,groupname,key):
		self.groups[groupname]=key


		



	def set_server_key(self,server_key):
		self.server_key=server_key