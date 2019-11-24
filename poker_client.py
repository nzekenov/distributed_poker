import tkinter
from tkinter import messagebox
import socket

def StartConnection (IPAddress, PortNumber):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((IPAddress,PortNumber))
    return server

#this function moves binary values to the left (part of hashing)
def leftrotate(x,c):
    return (x << c)&0xFFFFFFFF | (x >> (32-c)&0x7FFFFFFF>>(32-c))

#sends username and receives challenge from server, then breaks alltogether into list
def makeHash(s,username,password):
    #send a command to server
    s.send(b"LOGIN " + bytes(username, "utf-8")+ b"\n")
    #receives challenge from the server
    message = s.recv(500)
    message = str(message,'utf-8')
    message = message.split()[2]
    #makes a text in given format
    message = password+message
    block = message
    block += "1"
    while len(block)!=509:
        block = block + "0"
    block += str(len(message)//100)
    block += str(len(message)//10)
    block += str(len(message)%10)
    #splits the text and stores it ASCII values
    M=[]
    for i in range(16):
        strSum = 0
        for j in range(32):
            strSum += ord(block[i*32:((i+1)*32)][j])
        M.append(strSum)
    #returns list of ASCII values
    return M

#store values of S (used for hashing)
def sValue():
    S = []
    S[0:15] = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22]
    S[16:31] = [5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20]
    S[32:47] = [4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23]
    S[48:63] = [6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21]
    return S

#store values of K (used for hashing)
def kValue():
    K = []
    K[0:3] = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee]
    K[4:7] = [0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501]
    K[8:11] = [0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be]
    K[12:15] = [0x6b901122,0xfd987193,0xa679438e,0x49b40821]
    K[16:19] = [0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa]
    K[20:23] = [0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8]
    K[24:27] = [0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed]
    K[28:31] = [0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a]
    K[32:35] = [0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c]
    K[36:39] = [0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70]
    K[40:43] = [0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05]
    K[44:47] = [0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665]
    K[48:51] = [0xf4292244,0x432aff97,0xab9423a7,0xfc93a039]
    K[52:55] = [0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1]
    K[56:59] = [0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1]
    K[60:63] = [0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391]
    return K

#store values of A,B,C,D,a0,b0,c0,d0 (used for hashing)
def abcdValues():
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476
    A = a0
    B = b0
    C = c0
    D = d0
    return a0,b0,c0,d0,A,B,C,D

#this is the loop where part of hashing goes on
def hashingLoop(A,B,C,D,K,M,S):
    for i in range(64):
        if 0<=i and i<=15:
            F = (B & C) | ((~B) & D)
            F = F & 0xFFFFFFFF
            g = i
        elif 16<=i and i<=31:
            F = (D & B) | ((~D) & C)
            F = F & 0xFFFFFFFF
            g = (5*i + 1) % 16
        elif 32<=i and i<=47:
            F = B ^ C ^ D
            F = F & 0xFFFFFFFF
            g = (3*i + 5) % 16
        elif 48<=i and i<=63:
            F = C ^ (B | (~D))
            F = F & 0xFFFFFFFF
            g = (7*i) % 16
        dTemp = D
        D = C
        C = B
        B = B + leftrotate((A+F+K[i]+M[g]),S[i])
        B = B & 0xFFFFFFFF
        A = dTemp
    return A,B,C,D

#logs in the server
def login (s, username, password):
    M = makeHash(s,username,password)
    #things that are not my level
    S = sValue()
    K = kValue()
    a0,b0,c0,d0,A,B,C,D = abcdValues()
    A,B,C,D = hashingLoop(A,B,C,D,K,M,S)
    a0 = (a0 + A) & 0xFFFFFFFF
    b0 = (b0 + B) & 0xFFFFFFFF
    c0 = (c0 + C) & 0xFFFFFFFF
    d0 = (d0 + D) & 0xFFFFFFFF
    result = str(a0)+str(b0)+str(c0)+str(d0)
    #end of hashing
    #sends login and hashed password+challenge to server
    s.send(b"LOGIN " + bytes(username+" "+result, "utf-8")+ b"\n")
    #retrieve answer from server
    message = s.recv(100)
    message = str(message,'utf-8')
    #if successfully logged in, welcome, else try again
    if message[0:16] == "Login Successful":
        return True
    else:
        return False

#retrieve the list of friends in chat
def getFriends(s):
    #sends request for the list of friends
    s.send(b"@friends \n")
    #retrieve the number of chars in answer from server
    message = s.recv(6)
    message = str(message, "utf-8")
    message = message[1:]
    size = int(message)
    #receive list of friends and do some format work
    message = s.recv(size-6)
    message = str(message, "utf-8")
    message = message.split("@")[3:]
    return message


#sends your message to friend
def sendMessage(s, friend, message):
    #calculate the size of your message to server
    l = 17+len(friend)+len(message)
    size = str(l//10000)+str(l//1000)+str(l//100)+str(l//10)+str(l%10)
    byteString = bytes(friend,"utf-8")+b"@"+bytes(message,"utf-8")+ b"\n"
    #send a message to server to send a message to friend
    s.send(b"@"+bytes(size,"utf-8")+b"@sendmsg@"+byteString)
    #receive an answer from the server
    message = s.recv(6)
    message = str(message, "utf-8")
    message = message[1:]
    size = int(message)
    message = s.recv(size-6)
    message = str(message, "utf-8")
    #show whether sent successfully or not
    if message[1:3]=="ok":
        return True
    return False


def getNumber(s):
    s.send(b"@rxmsg \n")
    #receive an answer from the server
    message = s.recv(6)
    message = str(message, "utf-8")
    message = message[1:]
    size = int(message)
    message = s.recv(size-6)
    message = str(message, "utf-8")
    #gets number of messages and files
    number = int(message[1])
    message = message.split("@")[2:]
    return message,number

def checkMail(s):
    message,number = getNumber(s)
    return number,message

def getTables(s):
    sendMessage(s,"nzekenov","/tables")
    number, message = checkMail(s)
    tables = []
    if number > 0:
        messages = getMail(s,message,number)
        print(len(messages))
        message = messages[0]
        number = message.split("/")[1]
        for i in range(number):
            tables.append(message.split("/")[i*2+2],message.split("/")[i*2+1])
    return tables




#returns all inbox files and messages
def getMail(s,message,number):
    messages = []
    #sort messages and files
    for i in range(number):
        if message[0] == "msg":
            #make username,message tuple
            a = (message[1],message[2])
            messages.append(a)
            message = message[3:]
        else:
            message = message[1:]
    #returns list received of messages and files
    return messages

class loginWnd():
    def __init__(self,root,socket):
        self.root = root
        self.socket = socket
        self.mainFrame = tkinter.Frame(root)
        self.mainFrame.grid(sticky = "wens")
        self.lbl1 = tkinter.Label(self.mainFrame, text = "Login")
        self.lbl2 = tkinter.Label(self.mainFrame, text = "Password")
        self.btn1 = tkinter.Button(self.mainFrame, text="OK",command=self.bp)
        self.box1 = tkinter.Entry(self.mainFrame)
        self.box2 = tkinter.Entry(self.mainFrame, show = "*")
        self.lbl1.grid(row = 0, column = 0)
        self.lbl2.grid(row = 1, column = 0)
        self.box1.grid(row = 0, column = 1)
        self.box2.grid(row = 1, column = 1)
        self.btn1.grid(row = 2, column = 1)
    

    def bp(self):
        #closes window if incorrect password/username entered
        while not login (self.socket, self.box1.get(), self.box2.get()):
            #there should be a window like "UNSUCCESSFUL"
            self.root.destroy()
        #logs in
        clogin = self.box1.get()
        sendMessage(self.socket,"nzekenov","/play")
        self.root.destroy()
        self.root = tkinter.Tk()
        self.root.title("Poker Client")
        self.app = pokerWnd(self.root,socket,clogin)
        self.root.mainloop()
        
class pokerWnd():
    def __init__(self,root,socket,mylogin):
        self.wnd = {}
        self.root = root
        self.socket = socket
        self.mylogin = mylogin
        self.mainFrame = tkinter.Frame(root)
        self.mainFrame.grid(sticky = "wens")
        self.lbl1 = tkinter.Label(self.mainFrame, text = "All Tables")
        self.listbox1_entries = getTables(self.socket)
        self.listbox1_widget = tkinter.Listbox(self.mainFrame)
        self.windows = {}
        self.btn1 = tkinter.Button(self.mainFrame, text = "Join Table",command = self.joinTable)
        for table in self.listbox1_entries:
            self.listbox1_widget.insert(tkinter.END, table)
        self.lbl1.grid(row = 0, column = 0)
        self.listbox1_widget.grid(row = 1, column = 0)
        self.btn1.grid(row = 2, column = 0)
        self.mainFrame.after(7000,self.alarm)
        

    def joinTable(self):
        sendMessage(self.socket,"nzekenov","/join/"+



        
    def alarm(self):
        self.listbox1_widget.delete(0,'end')
        self.listbox1_entries = getTables(self.socket)
        for user in self.listbox1_entries:
            self.listbox1_widget.insert(tkinter.END, user)
        self.mainFrame.after(7000,self.alarm)
        
"""   
class chatWnd():      
    def __init__(self,root,socket,friend,mylogin,message,file,windows,wnd):
        self.wnd = wnd
        self.windows = windows
        self.message = message
        self.file = file
        self.socket = socket
        self.mylogin = mylogin
        self.friend = friend
        if windows[friend]==False:
            self.mainFrame = tkinter.Frame(root)
            self.mainFrame.grid()
            self.txt1 = tkinter.Text(self.mainFrame)
            self.txt2 = tkinter.Text(self.mainFrame, height = 20)
            self.btn1 = tkinter.Button(self.mainFrame,text = "Send Message",command = self.sendMsg)
            self.btn2 = tkinter.Button(self.mainFrame,text = "Send File",command = self.sendFileBtn)
            self.txt1.config(height = 10)
            self.txt2.config(height = 7)
            self.btn1.config(height = 5)
            self.btn2.config(height = 5, width = 20)
            self.txt1.grid()
            self.txt2.grid(row = 1, column = 0)
            self.btn1.grid(row = 1, column = 1)
            self.btn2.grid(row = 2)
            self.txt1.config(state='disabled')
            self.windows[friend] = True
        self.mainFrame.after(1000, self.update)
        
    def sendMsg(self):
        if sendMessage(self.socket, self.friend, self.txt2.get("1.0","end-1c")):
            self.txt1.config(state='normal')
            self.txt1.insert(tkinter.END, self.mylogin + ": " +self.txt2.get("1.0","end-1c") + "\n")
            self.txt1.config(state='disabled')
            self.txt2.delete("1.0",'end')
        else:
            self.txt1.config(state='normal')
            self.txt1.insert(tkinter.END, "Error sending message to " + self.friend + ". Please try again. \n")
            self.txt1.config(state='disabled')
            self.txt2.delete("1.0",'end')

    #function that sends file when "Send File" button is pressed      
    def sendFileBtn(self):
        #choose file from documents(only current directory is available)
        filename = askopenfilename()
        filename = os.path.split(filename)[1]
        if sendFile(self.socket,self.friend,filename):
            self.txt1.config(state='normal')
            self.txt1.insert(tkinter.END, self.mylogin + ": File " +filename + " sent successfully. \n")
            self.txt1.config(state='disabled')
        
    def update(self):
        for (user,m) in self.message:
            if user == self.friend:
                self.txt1.config(state='normal')
                self.txt1.insert(tkinter.END, self.friend + ": " + m + "\n")
                self.txt1.config(state='disabled')
            else:
                if self.windows[user]==False:
                    self.wnd[user] = tkinter.Toplevel()
                    app = chatWnd(self.wnd[user],self.socket,user,self.mylogin,self.message,self.file,self.windows,self.wnd)
                    self.wnd[user].geometry("800x650")
                    self.wnd[user].title("Chat with " + user)
                    self.wnd[user].mainloop()
                else:
                    self.wnd[user].message = [(user,m)]+self.message[1:]
                    print(self.wnd[user].message)
                    self.wnd[user].update()
    
        self.message = self.message[1:]
        for (user,f) in self.file:
            if user == self.friend:
                self.txt1.config(state='normal')
                self.txt1.insert(tkinter.END, self.friend + ": Sent a file" + f + "\n")
                self.txt1.config(state='disabled')
            else:
                if self.windows[user]==False:
                    self.wnd[user] = tkinter.Toplevel()
                    app = chatWnd(self.wnd[user],self.socket,user,self.mylogin,self.message,self.file,self.windows,self.wnd)
                    self.wnd[user].geometry("800x650")
                    self.wnd[user].title("Chat with " + user)
                    self.wnd[user].mainloop()
        self.file = self.file[1:]
        number, messages = checkMail(self.socket)
        self.message,self.file = getMail(self.socket,messages,number)
        self.mainFrame.after(1000,self.update)
"""
socket = StartConnection("86.36.46.10", 15112)
wnd = tkinter.Tk()
wnd.title("Sign in")
theApp = loginWnd(wnd,socket)
wnd.mainloop()

