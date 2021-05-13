
class user:
    def __init__(self,name,username,password):
        self.name=name
        self.username=username      #name appended wih roll no. so username will be unique for every user
        self.password=password
        self.curr_ip=0
        self.curr_port=0
        self.groupList=[]            #list of group names this user is part of
        
        # self.isOnline=False          #boolean to denote user is online or not

    #Function to return user's ip and port
    def getIpPort(self):
        return self.curr_ip,self.curr_port
    def setIpPort(self,ip,port):
        self.curr_ip=ip
        self.curr_port=port

    #function receives username,password and dictionary of users: {'username':'password'}
    #returns 1: userid password matches, 0 if userid matches but wrong password, -1 if user doesn't exist
    def signIn(self,username,password) :
        if self.password == password and self.username == username :
            return True
        else :
            return False
            

        
    
    # #Function to log user out of chat application
    # def signOut(self):
    #     isOnline=False

    #Function to display all groups the user is a part of
    def showGroups(self):
        if groupList==[]:
            sys.stderr.write("User is not part of any group yet.")
        else:
            for group in groupList:
                print(group)


    
    #Function to join group
    def joinGroup(self,groupName,key):
        if groupName not in self.groupList :
            self.groupList.append((groupName,key))

       


    
    #def broadcast a msg/file to a group
    def broadcastToGroup(self,messageObj, groupName):
        pass

    #def send msg/file to single user
    def sendToUser(self,messageObj, username):
        pass
