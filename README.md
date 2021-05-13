# sns-chat-application

### About the Project
It is an end to end messaging system like Whatsapp . It is a multiclient chat application with a server component. One user can send text messages ,files,JPEG to other individuals as well as in the groups.The message is encrypted using the Triple DES and key will be Diffe-Hellman key type exchange between clients.
### Features Implemented
1. It supports sign up ,sign in send message,join group,create group,list group features.Each user can join multiple chat rooms.If one user sends a message to a group it is send to all the members.
2. All the functions are implemented with the help of classes to make it more user friendly named Client, Diffie_Helman, DES , user, Server.
3. When connection is established between client and server ,private Diffehelman key is shared between them . Message is encrypted using DES for performing all the functions from login to list_group. 
5. When a group is created by user,it is automatically joind into it ,no need to further call join group. 
6. In Join_group,if group doesnt exist then group is created and joind by the user.The corresponding group is added in group list and key of every group_name is stored seprated in a dictionary.
### Issues to be fixed
1. It is considered that once a user login,it will never logout.This means we didnt hanlde the case when user is disconnected then how to send the message. In that case ,we need to store all the data and send when user again establish connection(this is not handled).
2. Load balancing of data is not fixed.All the clients request to a single server .There is a single server thus we cannot  distribute the load between multiple servers when large number of request is queued.

### Machine dependencies
1. Should be able to execute .py files (prefereably python3 should be installed)
2. Should have des module installed (pip install des / pip3 install des)

### How to run the application-
1. Open a terminal with present working directory as the root folder of this application
2. command to run: `python3 server.py`. This will start the server.
3. In another terminal open client with command: `python3 client.py`.
4. A list of commands supported will be displayed. Start entering commands from that list as desired.
5. For every new client to join the server, follow step 3.

### Implementation
### Server side address highlighted, active connection status shown, client side activity result displayed - ![alt text](https://github.com/nayanika0208/sns-chat-application/blob/master/6.png)
### User Creation  ![alt text](https://github.com/nayanika0208/sns-chat-application/blob/master/1.png)
### User Validation  ![alt text](https://github.com/nayanika0208/sns-chat-application/blob/master/2.png)
### User Joining Group and Listing Groups  ![alt text](https://github.com/nayanika0208/sns-chat-application/blob/master/3.png)
### Sending File to Group  ![alt text](https://github.com/nayanika0208/sns-chat-application/blob/master/4.png)
### Sending Image to User  ![alt text](https://github.com/nayanika0208/sns-chat-application/blob/master/5.png)
