from Crypto.Util import number
import random
from sympy.ntheory import factorint


class Diffie_Hellman:
	roll_no=2020202019
	def __init__(self):
		self.mod_pub=number.getPrime(192)
		self.exp_pub=self.getprimitiveroot(self.mod_pub)

	def getprimitiveroot(self,n):
		# prime_no_list=factorint(n).keys()
		# print(prime_no_list)
		phi=n-1
		prime_no_list=factorint(phi).keys()
		print(prime_no_list)
		flag=True
		already_done=[]
		while flag:
			possible_key=random.randint(2,n)

			flag=False
			if possible_key not in already_done:
				print(possible_key)
				for i in prime_no_list:
					if(pow(possible_key,phi//i,n)==1):
						flag=True
						already_done.append(possible_key)
						break
			else:
				print("dd:"+possible_key)
				flag=True

		return possible_key 

	def print_keys(self):
		print()
		print(self.mod_pub)
		print(self.exp_pub)



key=Diffie_Hellman()
key.print_keys()
