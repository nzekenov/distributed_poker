import tkinter
from PIL import ImageTk
import PIL.Image
from tkinter import *
from tkinter import simpledialog
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


#returns all inbox files and messages
def getMail(s,message,number):
    messages = []
    #sort messages and files
    for i in range(number):
        if message[0] == "msg":
            #make message list
            a = message[2]
            messages.append(a)
            message = message[3:]
        else:
            message = message[1:]
    #returns list received of messages and files
    return messages

#window where user enters its login info
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
            #there should be a window like "UNSUCCESSFUL" (IN FUTURE)
            self.root.destroy()
        #logs in
        #opens next window where all tables are diplayed
        sendMessage(self.socket,"dealer","/play")
        clogin = self.box1.get()
        self.root.destroy()
        self.root = tkinter.Tk()
        self.root.title("Poker Client")
        self.app = pokerWnd(self.root,socket,clogin)
        self.root.mainloop()

#CLASS Player
class Player(object):
    def __init__(self,username,currentChips):
        self.username = username
        self.currentChips = currentChips
        self.cards = []
        self.table = table

class Card(object):
    def __init__(self,value,suit):
        self.value = value
        self.suit = suit


#window with all avaliable table
class pokerWnd():
    def __init__(self,root,socket,mylogin):
        self.leftmsg = []
        self.root = root
        self.socket = socket
        self.mylogin = mylogin
        self.mainFrame = tkinter.Frame(root)
        #sends a message to dealer that he is playing
        self.mainFrame.grid(sticky = "wens")
        self.lbl1 = tkinter.Label(self.mainFrame, text = "All Tables")
        #fills the listbox with currently available tables
        sendMessage(self.socket,"dealer","/tables")
        self.listbox1_widget = tkinter.Listbox(self.mainFrame)
        self.mainFrame.after(2000,self.getTables)
        #button for opening a chosen table
        self.btn1 = tkinter.Button(self.mainFrame, text = "Open Table",command = lambda: self.joinTable(str(self.listbox1_widget.get(self.listbox1_widget.curselection()))))
        self.lbl1.grid(row = 0, column = 0)
        self.listbox1_widget.grid(row = 1, column = 0)
        self.btn1.grid(row = 2, column = 0)
        self.getCommands()
        self.mainFrame.after(100,self.alarm)

    def getTables(self):
        number, message = checkMail(self.socket)
        self.listbox1_entries = []
        self.listbox1_widget.delete(0,'end')
        tables = []
        i = 0
        messages = getMail(self.socket,message,number)
        while i <= number and messages[i].split("/")[1]!="tables":
            messages.append(messages[i])
            i+=1
        print(messages[i]+" HAHAHAHAAHHA")
        for j in range(int(messages[i].split("/")[2])):
            tables.append(messages[i].split("/")[2+(j*2)+1])
        print(tables)
        print("ARE TABLES")
        self.listbox1_entries += tables
        print(self.listbox1_entries)
        print("SHOULD BE ADDED")
        for table in self.listbox1_entries:
            self.listbox1_widget.insert(tkinter.END, table)
        if i < number:
            self.leftmsg = messages[i+1:]
            print(messages[i+1:])
            print("SENT TO NEXT")

    #method of getting all commands
    def getCommands(self):
        messages = self.leftmsg
        print(messages)
        print("ARE FREAKING MESSSAGES")
        for i in range(len(messages)):
            if messages[i].split("/")[1] == "ok":
                print(messages[i])
                print(messages[i].split("/")[2])
                if messages[i].split("/")[2] == "joinTable":
                    print("GOODBYE")
                    print(messages[i+1:])
                    self.root.destroy()
                    self.root = tkinter.Tk()
                    self.root.title("Table")
                    app = tableWnd(self.root,self.socket,self.mylogin,messages[i+1:])
                    self.root.mainloop()



    def joinTable(self,tableId):
        answer = simpledialog.askstring("Input", "How many chips to use?",parent=self.mainFrame)
        print(answer)
        sendMessage(self.socket,"dealer","/join/"+tableId+"/"+answer)

    def alarm(self):
        sendMessage(self.socket,"dealer","/tables")
        self.mainFrame.after(2000,self.getTables)
        self.getCommands()
        self.leftmsg = []
        self.mainFrame.after(5000,self.alarm)

def rotate(l,n):
    return l[n:] + l[:n]

class tableWnd():
    def __init__(self,root,socket,mylogin,messages):
        self.players = []
        self.players1 = []
        self.wnd = wnd
        self.socket = socket
        self.mylogin = mylogin
        self.messages = messages
        self.center = 0
        print(self.messages)
        self.mainFrame = tkinter.Frame(root)
        self.mainFrame.grid()
        self.canvas = tkinter.Canvas(self.mainFrame,width = 600, height = 416)
        self.canvas.grid()
        image = PIL.ImageTk.PhotoImage(PIL.Image.open("images/63.gif").resize((600, 416), PIL.Image.ANTIALIAS))
        self.canvas.background = image
        self.bg = self.canvas.create_image(0,0,anchor=tkinter.NW,image=image)
        self.btn4 = tkinter.Button(self.canvas, text = "Leave Table", command = self.leave)
        button4 = self.canvas.create_window(450,20, anchor=tkinter.NW, window = self.btn4)
        self.lbl1 = tkinter.Label(self.mainFrame,text="None")
        playername= self.canvas.create_window(40, 50, anchor=tkinter.NW, window=self.lbl1)
        self.lbl2 = tkinter.Label(self.mainFrame,text="None")
        playername = self.canvas.create_window(50, 280, anchor=tkinter.NW, window=self.lbl2)
        self.lbl3 = tkinter.Label(self.mainFrame,text="None")
        playername = self.canvas.create_window(270, 330, anchor=tkinter.NW, window=self.lbl3)
        self.lbl4 = tkinter.Label(self.mainFrame,text="None")
        playername = self.canvas.create_window(490, 280, anchor=tkinter.NW, window=self.lbl4)
        self.lbl5 = tkinter.Label(self.mainFrame,text="None")
        playername = self.canvas.create_window(500, 50, anchor=tkinter.NW, window=self.lbl5)
        #self.btn1 = tkinter.Button(self.canvas, text = "Check/Call",command = self.check)
        #button1 = self.canvas.create_window(265, 300, anchor=tkinter.NW, window=self.btn1)
        #self.btn2 = tkinter.Button(self.mainFrame, text = "Fold",command = self.fold)
        #button2 = self.canvas.create_window(360, 300, anchor=tkinter.NW, window=self.btn2)
        #self.btn3 = tkinter.Button(self.mainFrame, text = "Bet/Raise",command = self.bet)
        #button3 = self.canvas.create_window(180, 300, anchor=tkinter.NW, window=self.btn3)
        #self.w = tkinter.Scale(self.mainFrame,from_=0, to=100,orient = HORIZONTAL)
        #scale = self.canvas.create_window(125,330, anchor = tkinter.NW,window=self.w)
        #card_back = PIL.Image.open('images/PNG/red_back.gif')
        #card_back = card_back.resize((35, 50), PIL.Image.ANTIALIAS)
        #self.card_back = PIL.ImageTk.PhotoImage(card_back)
        #central cards
        #cardimage = self.canvas.create_image(195, 160, anchor=tkinter.NW, image=self.card_back)
        #cardimage = self.canvas.create_image(240, 160, anchor=tkinter.NW, image=self.card_back)
        #cardimage = self.canvas.create_image(285, 160, anchor=tkinter.NW, image=self.card_back)
        #cardimage = self.canvas.create_image(330, 160, anchor=tkinter.NW, image=self.card_back)
        #cardimage = self.canvas.create_image(375, 160, anchor=tkinter.NW, image=self.card_back)
        #card_back = card_back.resize((25, 40), PIL.Image.ANTIALIAS)
        #self.card_back1 = PIL.ImageTk.PhotoImage(card_back)
        #1 cards
        #cardimage = self.canvas.create_image(100, 100, anchor=tkinter.NW, image=self.card_back1)
        #cardimage = self.canvas.create_image(130, 100, anchor=tkinter.NW, image=self.card_back1)
        #2 cards
        #cardimage = self.canvas.create_image(100, 220, anchor=tkinter.NW, image=self.card_back1)
        #cardimage = self.canvas.create_image(130, 220, anchor=tkinter.NW, image=self.card_back1)
        #4 cards
        #cardimage = self.canvas.create_image(440, 220, anchor=tkinter.NW, image=self.card_back1)
        #cardimage = self.canvas.create_image(470, 220, anchor=tkinter.NW, image=self.card_back1)
        #5 cards
        #cardimage = self.canvas.create_image(440, 100, anchor=tkinter.NW, image=self.card_back1)
        #cardimage = self.canvas.create_image(470, 100, anchor=tkinter.NW, image=self.card_back1)
        self.mainFrame.after(500,self.update)

    def leave(self):
        sendMessage(self.socket,"dealer","/leave")


#once user moves, buttons disappear
    def bet(self):
        sendMessage(self.socket,"dealer","/bet/"+str(self.w.get()))
        self.btn1.destroy()
        self.btn2.destroy()
        self.btn3.destroy()
        self.w.destroy()


    def check(self):
        sendMessage(self.socket,"dealer","/check")
        self.btn1.destroy()
        self.btn2.destroy()
        self.btn3.destroy()
        self.w.destroy()

    def fold(self):
        sendMessage(self.socket,"dealer","/fold")
        self.btn1.destroy()
        self.btn2.destroy()
        self.btn3.destroy()
        self.w.destroy()

    def getPlayers(self):
        number, message = checkMail(self.socket)
        self.players = []
        players = []
        messages = self.messages + getMail(self.socket,message,number)
        print("ALL MESSAGES ARE")
        print(messages)
        i = 0
        while i <= len(messages) and messages[i].split("/")[1]!="players":
            messages.append(messages[i])
            i+=1
        for j in range(int(messages[i].split("/")[2])):
            players.append(messages[i].split("/")[3+2*j])
        print(players)
        print(self.mylogin)
        self.players = players
        if len(self.players)<5:
            for j in range(5-len(self.players)):
                self.players.append(None)
        players = self.players
        print(players)
        while players[2]!=self.mylogin:
            print("High")
            players = rotate(players,1)
        print(players)
        self.players1 = players
        #1 username
        if players[0] != None:
            self.lbl1 = tkinter.Label(self.mainFrame,text=players[0])
            playername= self.canvas.create_window(40, 50, anchor=tkinter.NW, window=self.lbl1)
        else:
            self.lbl1.destroy()
        #2 username
        if players[1] != None:
            self.lbl2 = tkinter.Label(self.mainFrame,text=players[1])
            playername = self.canvas.create_window(50, 280, anchor=tkinter.NW, window=self.lbl2)
        else:
            self.lbl2.destroy()
        #3 username
        if players[2] != None:
            self.lbl3 = tkinter.Label(self.mainFrame,text=players[2])
            playername = self.canvas.create_window(270, 330, anchor=tkinter.NW, window=self.lbl3)
        else:
            self.lbl3.destroy()
        #4 username
        if players[3] != None:
            self.lbl4 = tkinter.Label(self.mainFrame,text=players[3])
            playername = self.canvas.create_window(490, 280, anchor=tkinter.NW, window=self.lbl4)
        else:
            self.lbl4.destroy()
        #5 username
        if players[4] != None:
            self.lbl5 = tkinter.Label(self.mainFrame,text=players[4])
            playername = self.canvas.create_window(500, 50, anchor=tkinter.NW, window=self.lbl5)
        else:
            self.lbl5.destroy()
        if i < len(messages):
            self.messages = messages[i+1:]
            print(messages[i+1:])
            print("SENT TO NEXT")
        print("RETURNING")
        print(players)
        return players

    def update(self):
        sendMessage(self.socket,"dealer","/players")
        current_players = self.mainFrame.after(1500,self.getPlayers)
        messages = self.messages
        print(messages)
        print("CAME FROM PLAYERS")
        for m in messages:
            if "/" in m:
                if m.split("/")[1] == "cards":
                    print("GAAGAGA")
                    if m.split("/")[2] == "your":
                        card_6 =  m.split("/")[3]+m.split("/")[4]
                        card_7 =  m.split("/")[5]+m.split("/")[6]
                        card6 = PIL.Image.open('images/PNG/'+card_6+'.gif')
                        card6 = card6.resize((35, 50), PIL.Image.ANTIALIAS)
                        card7 = PIL.Image.open('images/PNG/'+card_7+'.gif')
                        card7 = card7.resize((35, 50), PIL.Image.ANTIALIAS)
                        self.card_6 = PIL.ImageTk.PhotoImage(card6)
                        self.card_7 = PIL.ImageTk.PhotoImage(card7)
                        cardimage = self.canvas.create_image(270, 240, anchor=tkinter.NW, image=self.card_6)
                        cardimage = self.canvas.create_image(310, 240, anchor=tkinter.NW, image=self.card_7)
                    elif m.split("/")[2] == "center":
                        print(m+"ARECARDS")
                        if self.center == 0:
                            card_1 =  m.split("/")[3]+m.split("/")[4]
                            card_2 =  m.split("/")[5]+m.split("/")[6]
                            card_3 =  m.split("/")[7]+m.split("/")[8]
                            print(card_1,card_2,card_3)
                            card1 = PIL.Image.open('images/PNG/'+card_1+'.gif')
                            card1 = card1.resize((35, 50), PIL.Image.ANTIALIAS)
                            card2 = PIL.Image.open('images/PNG/'+card_2+'.gif')
                            card2 = card2.resize((35, 50), PIL.Image.ANTIALIAS)
                            card3 = PIL.Image.open('images/PNG/'+card_3+'.gif')
                            card3 = card3.resize((35, 50), PIL.Image.ANTIALIAS)
                            self.card_1 = PIL.ImageTk.PhotoImage(card1)
                            self.card_2 = PIL.ImageTk.PhotoImage(card2)
                            self.card_3 = PIL.ImageTk.PhotoImage(card3)
                            cardimage = self.canvas.create_image(195, 160, anchor=tkinter.NW, image=self.card_1)
                            cardimage = self.canvas.create_image(240, 160, anchor=tkinter.NW, image=self.card_2)
                            cardimage = self.canvas.create_image(285, 160, anchor=tkinter.NW, image=self.card_3)
                            self.center += 1
                        elif self.center == 1:
                            card_4 =  m.split("/")[3]+m.split("/")[4]
                            card4 = PIL.Image.open('images/PNG/'+card_4+'.gif')
                            card4 = card4.resize((35, 50), PIL.Image.ANTIALIAS)
                            self.card_4 = PIL.ImageTk.PhotoImage(card4)
                            cardimage = self.canvas.create_image(330, 160, anchor=tkinter.NW, image=self.card_4)
                            self.center += 1
                        else:
                            card_5 =  m.split("/")[3]+m.split("/")[4]
                            card5 = PIL.Image.open('images/PNG/'+card_5+'.gif')
                            card5 = card5.resize((35, 50), PIL.Image.ANTIALIAS)
                            self.card_5 = PIL.ImageTk.PhotoImage(card5)
                            cardimage = self.canvas.create_image(375, 160, anchor=tkinter.NW, image=self.card_5)
                            self.center += 1

                #if it is player's turn, buttons appear
                elif m.split("/")[1] == "move":
                    print(m)
                    self.btn1 = tkinter.Button(self.canvas, text = "Check/Call",command = self.check)
                    button1 = self.canvas.create_window(265, 300, anchor=tkinter.NW, window=self.btn1)
                    self.btn2 = tkinter.Button(self.mainFrame, text = "Fold",command = self.fold)
                    button2 = self.canvas.create_window(360, 300, anchor=tkinter.NW, window=self.btn2)
                    self.btn3 = tkinter.Button(self.mainFrame, text = "Bet/Raise",command = self.bet)
                    button3 = self.canvas.create_window(180, 300, anchor=tkinter.NW, window=self.btn3)
                    self.w = tkinter.Scale(self.mainFrame,from_=0, to=100,orient = HORIZONTAL)
                    scale = self.canvas.create_window(125,330, anchor = tkinter.NW,window=self.w)

                elif m.split("/")[1] == "won":
                    messagebox.showinfo("Game End","You won "+ m.split("/")[2])

                elif m.split("/")[1] == "leave" or m.split("/")[1] == "end":
                    self.root.destroy()
                    self.root = tkinter.Tk()
                    self.root.title("Table")
                    app = pokerWnd(self.root,self.socket,self.mylogin)
                    self.root.mainloop()
                elif m.split("/")[1] == "no":
                    messagebox.showerror("Error", m.split("/")[2])
                

        self.messages = []
        self.mainFrame.after(500,self.update)






socket = StartConnection("86.36.46.10", 15112)
wnd = tkinter.Tk()
wnd.title("Sign in")
app = loginWnd(wnd,socket)
wnd.mainloop()
