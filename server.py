import socket
import threading
from user import user
import random
from security import Diffie_Hellman,DES
import hashlib

PORT = 5051 

SERVER = "127.0.0.2"
HEADER = 64
# SERVER = socket.gethostbyname(socket.gethostname())
# ADDR = (SERVER,PORT)
FORMAT = "utf-8"

DISCONNECT_MESSAGE="!DISCONNECT"



#group class contains a group_id and a list of users who are part of it
class Group :
	def __init__(self,id):
		self.group_id = id
		self.users_list=set()
		self.key=random.getrandbits(192)

	def show_members(self) :
		print(self.group_id," : ",self.users_list)

	def add_member(self,user_id) :
		self.users_list.add(user_id)
	def no_of_members(self) :
		return len(self.users_list)
	def members_list(self):
		return self.users_list

		
		
#server class to handle all server related works
class Server :
	def __init__(self, server_ip, server_port):
		self.IP = server_ip            #ip of server
		self.PORT = server_port		   #port of server
		self.clientConnections = []    #active connection list of clients connected to this server
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       #creating socket object named server
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     #setting socket up
		self.ADDR=(self.IP,self.PORT)  #tuple of server ip and server address
		self.user_dict={}              #dictionary of user id to user object
		self.group_dict={}             #dictionary of groupids to list of user objects
		self.private_key=self.get_privatekey()
		self.imd_key=Diffie_Hellman(self.private_key).intermediate_key
		self.shared_key={}

	def get_privatekey(self):
		roll_no=2020202019
		pri_key=random.getrandbits(192)
		pri_key+=roll_no
		pri_key=str(pri_key)
		pri_key=hashlib.sha256(pri_key.encode())
		pri_key=pri_key.hexdigest()		
		pri_key=pri_key[:11]
		pri_key=int(pri_key,16)
		return pri_key

	def server_start(self):

		try:
			self.server.bind(self.ADDR)             #binding the created socket to server ip and port (ADDR=(IP,PORT))

		except socket.error as e:
			print(str(e))
		self.server.listen(10)
		self.print_cmd(f"[*] Starting server ({self.IP}) on port {self.PORT}")
		while True :                                
			connection,address=self.server.accept()         #accepting client socket, address(ip,port) from client
			thread=threading.Thread(target=self.handle_client,args=(connection,address))
			thread.start()
			print(f"[ACTIVE CONNECTIONS] {threading.activeCount()-1}")

	def print_cmd(self,comment):
		print("\033[96m {}\033[00m".format(comment))

	#Function to handle client requests concurrently (one spawned for every client requesting a connection)
	def handle_client(self,conn,address) :
		self.print_cmd(f"[NEW CONNECTION] {address} connected ")
		msg_length=conn.recv(HEADER).decode(FORMAT)
		msg_length=int(msg_length)	                          #extract msg length to receive
		msg=conn.recv(msg_length)
		sk=Diffie_Hellman(self.private_key).create_shared_key(msg)
		
		self.send(self.imd_key,conn)
		msg=address[0]+" "+str(address[1])
		self.send(msg,conn)
		self.shared_key[address[1]]=sk
		connected=True
		while connected :
			msg_length=conn.recv(HEADER).decode(FORMAT)              #receive size of msg from client to handle (put in buffer size of HEADER(64 B))
			
			if msg_length :
				msg_length=int(msg_length)	                          #extract msg length to receive
				msg=conn.recv(msg_length)              #set this as new buffer size to recieve actual message
				msg=DES(self.shared_key[address[1]]).decryption(msg)
				if msg == DISCONNECT_MESSAGE :
					connected=False
				msg_list=msg.split(" ")

				if msg_list[0] == "CREATE_USER" :                    #command received= ['CREATE_USER', 'name', 'username', 'password']

					if(len(msg_list) != 4 ):
						msg="0"
						self.send_encrypted(msg,conn,address)
					elif msg_list[2] in self.user_dict:
						msg="-1"
						self.send_encrypted(msg,conn,address)
					else :
						new_user = user(msg_list[1],msg_list[2],msg_list[3])  #creating user object by calling its constuctor
						self.user_dict[msg_list[2]] = new_user                                      #adding user to server's list
						msg="1"
						self.send_encrypted(msg,conn,address)

				elif msg_list[0] =="LOGIN" :                       #command received= ['LOGIN','username','password']

					if(len(msg_list) != 3 ):
						print("[LOGIN unsuccessful]")
						msg="0"
						self.send_encrypted(msg,conn,address)
					else :			
						username = msg_list[1]
						password = msg_list[2]

						try :

							curr_user=self.user_dict[username]         #adding user to server's user list
							login_status=curr_user.signIn(username,password)
							if login_status == True :
								curr_user.setIpPort(address[0],address[1])
								self.print_cmd("checking new user signed in"+str(new_user.getIpPort()))
								msg="1"
								self.send_encrypted(msg,conn,address)

							else :
								print("[LOGIN unsuccessful]")
								msg="-1"
								self.send_encrypted(msg,conn,address)
						except :
							print("[LOGIN unsuccessful RN]")
							msg="-2"
							self.send_encrypted(msg,conn,address)
						
								
				elif msg_list[0] == "SEND" :                     #command received= ['SEND','sender','receiver']
					#self.print_cmd("Please send the message")           
					if len(msg_list) != 3:
						print("[SEND unsuccessful]")
						msg="0"
						self.send_encrypted(msg,conn,address)
					elif msg_list[2] not in self.user_dict:
						msg="-1"
						self.send_encrypted(msg,conn,address)
					elif  len(msg_list) == 3:
						addr=self.user_dict[msg_list[2]].getIpPort()
						msg=str(addr[0])+" "+ str(addr[1])
						self.send_encrypted(msg,conn,address)

				elif msg_list[0] == "SEND_TO_GROUP" :                     #command received= ['SEND_TO_GROUP','username','groupname']
					#print("Please send the message")			
					             
					if len(msg_list) != 3 :
						print("[SEND_TO_GROUP unsuccessful]")						
						msg="False"
						self.send_encrypted(msg,conn,address)
					elif  len(msg_list) == 3:
						no_members=self.group_dict[msg_list[2]].no_of_members()
						
						self.send_encrypted(no_members,conn,address)
						list_member=self.group_dict[msg_list[2]].members_list()
						for i in list_member:
							if i!=msg_list[1]:
								addr=self.user_dict[i].getIpPort()						
								msg=str(addr[0])+" "+ str(addr[1])
								self.send_encrypted(msg,conn,address)



				elif msg_list[0] == "JOIN" :                     #command received= ['JOIN','username','groupname']
					#self.print_cmd("Please JOIN the group")
					if len(msg_list) != 3 :
						print("[JOIN unsuccessful]")
						msg="False"
						self.send_encrypted(msg,conn,address)
					else :
						if msg_list[2] not in self.group_dict:
							self.create_group(msg_list[2],msg_list[1],conn,address)
						else :
							self.group_dict[msg_list[2]].add_member(msg_list[1])    #add user to group object's list
							self.user_dict[msg_list[1]].joinGroup(msg_list[2],self.group_dict[msg_list[2]].key)      #add groupname to user class' grouplist
							msg=self.group_dict[msg_list[2]].key
							self.send_encrypted(msg,conn,address)

				elif msg_list[0] == "CREATE" :                  #command received= ['CREATE','username''groupname']  
					if len(msg_list) != 3 :
						print("[CREATE unsuccessful]")
						msg="False"
						self.send_encrypted(msg,conn,address)
					else :
						self.create_group(msg_list[2],msg_list[1],conn,address)

					
				elif msg_list[0] == "LIST" :                     #command received=['LIST']
					groups= list(self.group_dict.keys())
					print("groups ",groups)
					msg=len(groups)
					self.send_encrypted(msg,conn,address)
					for i in groups:
						msg=str(i)+":"+str(self.group_dict[i].no_of_members())
						self.send_encrypted(msg,conn,address)

		conn.close()	                                         #closing the connection with a client

	def create_group(self,grp,user_id,conn,address):
		if grp in self.group_dict.keys() :
			print("[CREATE_GROUP unsuccessful]")
			msg="False"
			self.send_encrypted(msg,conn,address)
		else :
			self.group_dict[grp]=Group(grp)                  #put newly created group object in server's group dictionary
			self.group_dict[grp].add_member(user_id)         #add user to group object's list
			self.user_dict[user_id].joinGroup(grp,self.group_dict[grp].key)			 #add groupname to user class' grouplist
			msg=self.group_dict[grp].key
			self.send_encrypted(msg,conn,address)

						
	#Function to send message from server to client on port->contained in "connection" variable				
	def send(self,msg,connection) :
		msg=str(msg)
		message = msg.encode(FORMAT)                     #encode msg in utf-8
		msg_length = len(message)                        #extract length of msg
		send_length = str(msg_length).encode(FORMAT)     #encode length to send before sending actual msg
		send_length += b' ' * (HEADER -len(send_length)) #pad it to fit the initial buffer size=HEADER (64B)
		connection.send(send_length)                     #send length
		connection.send(message)						 #send message

	def send_encrypted(self,msg,connection,address):
		msg=str(msg)
		message=DES(self.shared_key[address[1]]).encryption(msg)                  
		msg_length = len(message)                        #extract length of msg
		send_length = str(msg_length).encode(FORMAT)     #encode length to send before sending actual msg
		send_length += b' ' * (HEADER -len(send_length)) #pad it to fit the initial buffer size=HEADER (64B)
		connection.send(send_length)                     #send length
		connection.send(message)	
    	
   

print("[STARTING] server is starting .... ")
server=Server(SERVER,PORT)                               #creating server object and initializing its ip and port
server.server_start()



