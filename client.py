import socket
import threading
from user_client import user_client
from security import Diffie_Hellman,DES
import sys
import os 
from math import ceil 
'''Global variables'''
PORT = 5051 
HEADER = 64
FORMAT = "utf-8"
SERVER = "127.0.0.2"
DISCONNECT_MESSAGE="!DISCONNECT"


###*******CLIENT CLASS*****###
class Client:
    def __init__(self, server_ip, port, client_ip):
        self.SERVER_IP = server_ip                              #server's ip to connect to
        self.PORT = port										#server's port to connect to
        self.CLIENT_IP = client_ip    							#client's own ip
        self.isLoggedIn=False  									#active status of client
        self.ADDR=(self.SERVER_IP,self.PORT)  							#tuple of server ip and server address
        print(f"[*] Host: {self.CLIENT_IP} | Port: {self.PORT}")

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    #socket object on client side
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
        self.current_userid=""
        self.my_group_list= set()




    def connectToServer(self):
        try:
            self.client.connect((self.ADDR))                      #establish connection with server on address ADDR=SERVER_IP,SERVER_PORT

        except socket.error as e:
            self.print_error(str(e))
            sys.exit()
        self.shared_key_server()
        thread=threading.Thread(target=self.listen_client)
        thread.start()
        
    def print_error(self,comment):
        print("\033[91m {}\033[00m".format(comment))
        print()
    
    def print_msg(self,comment):
        print("\033[93m {}\033[00m".format(comment))
        print()

    def operate(self):
        print("\nPlease choose from one of the following commands")
        print("CREATE_USER <NAME> <USER_NAME> <PASSWORD>")
        print("LOGIN <USER_NAME> <PASSWORD>")
        print("JOIN <GROUP_NAME> ")
        print("CREATE <GROUP_NAME> ")
        print("LIST")
        print("SEND <USER_NAME> <MESSAGE>")
        print("SEND_TO_GROUP <GROUP_NAME(S)> <MESSAGE>")
        print("SEND FILE <USER_NAME> <FILENAME>")
        print("SEND_TO_GROUP FILE <GROUP_NAME(S)> <FILENAME>")
        print()
        quit=False
        while quit == False :
            my_input=input()
            my_input_list=my_input.split()
            if (len(my_input_list)!=0) :
                if(my_input_list[0] == "CREATE_USER") :
                    self.encrypted_send(my_input,self.user_key_pair.server_key)
                    self.create_user(my_input_list)
                elif(my_input_list[0] == "CREATE")	:
                    self.create_group(my_input_list) 
                elif(my_input_list[0] == "SEND")	:
                    self.send_message(my_input_list) 
                elif(my_input_list[0] == "LOGIN")	:
                    self.encrypted_send(my_input,self.user_key_pair.server_key)
                    self.login_user(my_input_list) 
                elif(my_input_list[0] == "JOIN")	:
                    self.join_group(my_input_list) 
                elif(my_input_list[0] == "LIST") :
                    self.encrypted_send(my_input,self.user_key_pair.server_key) 	
                    self.list_group(my_input_list) 
                elif(my_input_list[0] == "SEND_TO_GROUP")	:
                    self.send_to_group(my_input_list)
                else:
                    self.print_error("Invalid command")
                    print()

	#function to handle message received from others over a socket
    def recieve_message(self,cli=None):
        if cli==None:
            cli=self.client
        msg=""
        msg_length=cli.recv(HEADER).decode(FORMAT)   #get length of  msg to receive by using initial buffer size of header=64B
        if msg_length :
            msg_length=int(msg_length)	                    #convert length to int as it was received in utf-8 format
            msg=cli.recv(msg_length).decode(FORMAT)	 #reset buffer size to received msg length size and receive msg
        return msg


    def recieve_message_decrypt(self,key,cli=None,file=None):
        if cli==None:
            cli=self.client
        msg=""
        msg_length=cli.recv(HEADER).decode(FORMAT)   #get length of  msg to receive by using initial buffer size of header=64B
        if msg_length :
            msg_length=int(msg_length)                      #convert length to int as it was received in utf-8 format
              
            if file==None:
                msg=cli.recv(msg_length)
                msg=DES(key).decryption(msg)
            else:
                msg=msg.encode(FORMAT)
                
                while msg_length:
                    msg1 = cli.recv(min(msg_length,102400))
                    
                    msg+=DES(key).decryption(msg1,1)
                    msg_length-=min(msg_length,102400)
                    
        return msg


    def create_user(self,command_list):
        msg=self.recieve_message_decrypt(self.user_key_pair.server_key)
        if msg =="1":
            self.print_msg("User created successfully")
        elif msg =="-1":
            self.print_error("Error: username already exists")
        else:
            self.print_error("Error: wrong number of arguments")

    def login_user(self,command_list):
        msg=self.recieve_message_decrypt(self.user_key_pair.server_key)
        if msg == "1":
            self.current_userid = command_list[1]
            self.isLoggedIn=True
            self.print_msg(str(command_list[1])+" logged in successfully")
        elif msg=="-1":
            self.print_msg("Invalid credentials")
        elif msg=="-2":
            self.print_msg("Username doesn't exist. Signup first")
        else:
            self.print_error("Wrong arguments")

    def create_group(self,command_list):
        if self.isLoggedIn == False :
            self.print_error("Please Login First")
        else :
            send_msg=command_list[0]+" "+ self.current_userid+" "+command_list[1]
            self.encrypted_send(send_msg,self.user_key_pair.server_key)
            msg=self.recieve_message_decrypt(self.user_key_pair.server_key)

            if(msg=="False") :
                self.print_error("Group exists! Please use JOIN command to join the group")
            else :
                self.print_msg(command_list[1]+" group created succesfully ")
                self.my_group_list.add(command_list[1])
                self.user_key_pair.joingroup(command_list[1],msg)

    def join_group(self,command_list):
        if self.isLoggedIn == False :
            self.print_error("Please Login First")
        else :
            send_msg=command_list[0]+" "+ self.current_userid+" "+command_list[1]
            self.encrypted_send(send_msg,self.user_key_pair.server_key)    		
            msg=self.recieve_message_decrypt(self.user_key_pair.server_key)

            if(msg=="False") :
                self.print_error("Invalid command")
            else :
                if command_list[1] in self.my_group_list:
                    self.print_error(str(self.current_userid)+" is already a member of "+str(command_list[1]))
                else:
                    self.print_msg(str(self.current_userid)+" joined group "+str(command_list[1])+" succesfully ")
                    self.my_group_list.add(command_list[1])
                    self.user_key_pair.joingroup(command_list[1],msg)

    def send_message(self,command_list):
        if len(command_list) < 3:
            self.print_error("Invalid command")
        elif command_list[1]=="FILE":
            if len(command_list) !=4 :
                self.print_error("Invalid command")
            else:
                self.send_message_file(command_list)
        else:
            temp_list = command_list[2:]
            temp_str=" ".join(temp_list)
            command_list=command_list[0:2]
            command_list.append(temp_str)
            self.send_message_msg(command_list)

    def send_message_msg(self,command_list):
        receiver=command_list[1]
        send_msg=command_list[0]+" "+ self.current_userid+" "+ receiver
        self.encrypted_send(send_msg,self.user_key_pair.server_key)
        msg=self.recieve_message_decrypt(self.user_key_pair.server_key)
        if msg=="0":
            self.print_error("Error:wrong arguments")
        elif msg=="-1":
            self.print_error("Receiver username not part of chat application")
        else:
            ip=msg.split(" ")[0]
            port=int(msg.split(" ")[1])
            message=command_list[2]
            thread1=threading.Thread(target=self.send_message_data,args=(ip,port,message))
            thread1.start()
            thread1.join()


    def send_message_file(self,command_list):
        receiver=command_list[2]
        send_msg=command_list[0]+" "+ self.current_userid+" "+ receiver
        self.encrypted_send(send_msg,self.user_key_pair.server_key)
        msg=self.recieve_message_decrypt(self.user_key_pair.server_key)
        if msg=="False":
            self.print_error("Invalid command")
        else:
            ip=msg.split(" ")[0]
            port=int(msg.split(" ")[1])
            filename=command_list[3]
            thread1=threading.Thread(target=self.send_message_filedata,args=(ip,port,filename))
            thread1.start()
            thread1.join()

    def send_message_data(self,ip,port,message,group=None):
        cli_server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:                       
            addr=(ip,port)
            cli_server.connect(addr)                      #establish connection with server on address ADDR=SERVER_IP,SERVER_PORT
            
        except socket.error as e:
            self.print_error(str(e))
            sys.exit()
        if group==None:
            self.send(self.user_key_pair.imd_key,cli_server)
            sk=self.recieve_message(cli_server)
            sk=Diffie_Hellman(self.user_key_pair.private_key).create_shared_key(sk)
            message=self.current_userid+" : "+message
        else:
            msg="GROUP "+group
            self.send(msg,cli_server)
            sk=self.user_key_pair.groups[group]
            sk=int(sk)
            message=self.current_userid+"->"+group+":"+message
        self.encrypted_send(message,sk,cli_server)


    def send_message_filedata(self,ip,port,filename,group=None):
        cli_server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:                       
            addr=(ip,port)
            cli_server.connect(addr)                      #establish connection with server on address ADDR=RECEIVER_IP,RECEIVER_PORT
            
        except socket.error as e:
            self.print_error(str(e))
            sys.exit()
        if group==None:
            self.send(self.user_key_pair.imd_key,cli_server)
            sk=self.recieve_message(cli_server)
            sk=Diffie_Hellman(self.user_key_pair.private_key).create_shared_key(sk)
            msg_type=self.current_userid+" : FILE= "+filename+"fIlE"
        else:
            msg="GROUP "+group
            self.send(msg,cli_server)
            sk=self.user_key_pair.groups[group]
            sk=int(sk)
            msg_type=self.current_userid+"->"+group+":"+"FILE= "+filename+"fIlE"
        self.encrypted_send(msg_type,sk,cli_server)
        self.encrypted_send(filename,sk,cli_server)
        try:
            
            fd=open(filename,"rb")
            file_size = os.path.getsize(filename)
            n=file_size/10240
            n=int(ceil(n))
            n1=str(n)
            self.encrypted_send(n1,sk,cli_server)
            for i in range(n):
                filedata=fd.read(10240)
                self.encrypted_send(filedata,sk,cli_server,1)
                
            fd.close()
            

            self.print_msg("file sent")
            
            
        except FileNotFoundError as f:
            self.print_error(str(f))     

    def list_group(self,command_list):
        msg=self.recieve_message_decrypt(self.user_key_pair.server_key)
        group_len=int(msg)
        if group_len==0:
            self.print_error("NO GROUPS")
        else:
            self.print_msg("GROUP LIST:")
            for i in range(0,group_len):
                msg=self.recieve_message_decrypt(self.user_key_pair.server_key)
                self.print_msg(msg)
                
    def send_to_group(self,command_list):
        if(len(command_list)<3):
            self.print_error("Invalid command")
        else:
            if command_list[1]=="FILE":
                groupnames=command_list[2].split(',')
                for i in groupnames:
                    if i not in self.my_group_list:
                        self.print_error("User not part of group: "+i)
                    else:
                        command_list[2]=i
                        thread2=threading.Thread(target=self.send_to_group_file,args=(command_list,))
                        thread2.start()
                        thread2.join()
            else:
                groupnames=command_list[1].split(',')
                for i in groupnames:
                    if i not in self.my_group_list:
                        self.print_error("User not part of group: "+i)
                    else:
                        command_list[1]=i
                        thread3=threading.Thread(target=self.send_to_group_msg,args=(command_list,))
                        thread3.start()
                        thread3.join()

    def send_to_group_msg(self,command_list):
        send_msg=command_list[0]+" "+ self.current_userid+" "+ command_list[1]

        self.encrypted_send(send_msg,self.user_key_pair.server_key)
        msg1=self.recieve_message_decrypt(self.user_key_pair.server_key)
        msg1=int(msg1)
        msg1-=1
        for i in range(msg1):
            msg=self.recieve_message_decrypt(self.user_key_pair.server_key)

            ip=msg.split(" ")[0]
            port=int(msg.split(" ")[1])
            message=command_list[2:]
            message=" ".join(message)
            group=command_list[1]
            thread1=threading.Thread(target=self.send_message_data,args=(ip,port,message,group))
            thread1.start()
            thread1.join()	

    def send_to_group_file(self,command_list):
        send_msg=command_list[0]+" "+ self.current_userid+" "+ command_list[2]

        self.encrypted_send(send_msg,self.user_key_pair.server_key)
        msg1=self.recieve_message_decrypt(self.user_key_pair.server_key)
        msg1=int(msg1)
        msg1-=1
        for i in range(msg1):
            msg=self.recieve_message_decrypt(self.user_key_pair.server_key)
            
            ip=msg.split(" ")[0]
            port=int(msg.split(" ")[1])

            thread1=threading.Thread(target=self.send_message_filedata,args=(ip,port,command_list[3],command_list[2]))
            thread1.start()
            thread1.join()
    	
    def send(self,msg,cli=None) :
        if cli==None:
            cli=self.client
        msg=str(msg)
        message = msg.encode(FORMAT)
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER -len(send_length))
        cli.send(send_length)
        cli.send(message)
		
    def shared_key_server(self):
        self.user_key_pair=user_client(self.current_userid)
        self.send(self.user_key_pair.imd_key)
        sk=self.recieve_message()
        sk=Diffie_Hellman(self.user_key_pair.private_key).create_shared_key(sk)
        self.user_key_pair.set_server_key(sk)
        ip_port=self.recieve_message()
        ip=ip_port.split()[0]
        port=int(ip_port.split()[1])
        self.CLI_ADDR=(ip,port)

    def encrypted_send(self,msg,key,cli=None,File=None):
        if cli==None:
            cli=self.client
        if File==None:    
            message=DES(key).encryption(msg)
        else:
            message=DES(key).encryption(msg,1)
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)                 
        send_length += b' ' * (HEADER -len(send_length))
        cli.send(send_length)
        
        cli.sendall(message)       


    def listen_client(self):
        try:
            
            print(self.CLI_ADDR)
            cli_server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cli_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
            cli_server.bind(self.CLI_ADDR)            
        except socket.error as e:
            self.print_error(str(e))

        cli_server.listen(5)
        while True : 

            connection,address=cli_server.accept()
            thread1=threading.Thread(target=self.handle_client,args=(connection,address))
            thread1.start()
            thread1.join()
            

    def handle_client(self,conn,address):
        msg=self.recieve_message(conn)
        if msg.startswith("GROUP"):
            sk=msg.split(" ")[1]
            sk=self.user_key_pair.groups[sk]
            sk=int(sk)
        else:            
            sk=Diffie_Hellman(self.user_key_pair.private_key).create_shared_key(msg)  
            self.send(self.user_key_pair.imd_key,conn)
        msg=self.recieve_message_decrypt(sk,conn)
        if msg.find("fIlE")!=-1:
            self.print_msg(msg[:-4])
            self.handle_client_file(conn,sk)
        else:
            self.print_msg(f"->{msg}")

    def handle_client_file(self,conn,sk):         
        try:
            file_name=self.recieve_message_decrypt(sk,conn) 
            n=self.recieve_message_decrypt(sk,conn)
            file_name1=file_name.split(".")
            file_name1=file_name1[0]+str(self.CLI_ADDR)+"."+file_name1[1]
            fd=open(file_name1,"wb")            
             
            for i in range(int(n)):
                file_data=self.recieve_message_decrypt(sk,conn,1)            
                fd.write(file_data)            
            fd.close()
            self.print_msg(f"->{file_name} received")
        except:
            self.print_error("Error in receiving file")


client =Client(SERVER,PORT,"127.0.0.1")
client.connectToServer()
client.operate()
		
	
