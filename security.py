
from des import DesKey



#pip install des
FORMAT = "utf-8"

class Diffie_Hellman:
	
	mod_pub=3343036042667233507069333705267738066150537335329373445649
	exp_pub=150449272774067166433654322282031043481528926326708716556
	def __init__(self,pri_key):
		
		self.private_key=pri_key
		self.intermediate_key=self.create_intermediate_key()
	

	def create_intermediate_key(self):
		intermediate_key=pow(self.exp_pub,self.private_key,self.mod_pub)
		return intermediate_key

	def create_shared_key(self,intermediate_key):
		
		intermediate_key=int(intermediate_key)
		shared_key=pow(intermediate_key,self.private_key,self.mod_pub)
		return shared_key

	




class DES:
	def __init__(self,key):
		
		key=key.to_bytes(24, byteorder='big')
		self.key=key
		self.create_cipher()

	def create_cipher(self):

		# try:
		# 	key2 = DES3.adjust_key_parity(self.key)

		# except ValueError:
		# 	pass
		# self.cipher = DES3.new(key1, DES3.MODE_CFB)
		# print(self.key)
		# key2=pad(self.key,24)
		# print(key2)
		assert(len(self.key) == 24)
		self.key1=DesKey(self.key)
		# print(self.key1.is_triple())

	def encryption(self,data,file=None):
		if file==None:
			data=data.encode(FORMAT)
		cipher_text=self.key1.encrypt(data, padding=True)
		return cipher_text

	def decryption(self,data,file=None):
				
		plain_text=self.key1.decrypt(data, padding=True)
		if file==None:	
			plain_text=plain_text.decode(FORMAT)		
		return plain_text



