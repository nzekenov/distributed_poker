import random, socket, tkinter

# NETWORK CONNNECTION FOR RECIEVEING COMMANDS
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

#returns all inbox files and messages
def getMail(s):
    message,number = getNumber(s)
    messages = []
    files = []
    #sort messages and files
    for i in range(number):
        if message[0] == "msg":
            #make username,message tuple
            a = (message[1],message[2])
            messages.append(a)
            message = message[3:]
        elif message[0] == "file":
            #make username,filename tuple
            a = (message[1],message[2])
            files.append(a)
            file = message[3]
            #save files in same folder
            with open(message[2],"x") as fileout:
                fileout.write(file)
                fileout.close
            message = message[4:]
    #returns list received of messages and files
    return (messages,files)

def sendMessage(s, friend, message):
    #calculate the size of your message to server
    l = 17+len(friend)+len(message)
    size = str(l)
    while len(size)<5:
        size = "0" + size
    print(size)
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
    print(message)
    return False

def SendMessage(s):
    friend = input("Please insert the username of the friend you would like to message: ")
    message = input("Please insert the message that you would like to send: ")
    if friend in getFriends(s):
        if sendMessage(s, friend, message): print ("Mesage sent to " + friend + " succesfully")
        else: print ("Error sending message to " + friend + ". Please try again.")
    else: print (friend, "is not a Friend. You must add them as a friend before you can message them.")

#class of one card, each card can have a value and suit
class Card(object):
    def __init__(self,value,suit):
        self.value = value
        self.suit = suit
        #each card is invisible initially
        self.visible = False

    #shows the card, if it is visible, otherwise "Card" (Backside)
    def __repr__(self):
        if self.visible == True:
            return str(self.value + " of " + self.suit)
        return "Card"

#RandomDeck
class RandomDeck(list):
    #initializes a list of random cards with 52 elements
    def __init__(self):
        suits = ["Spades", "Hearts", "Diamonds", "Clubs"]
        values = {2:"Two", 3:"Three", 4:"Four", 5:"Five", 6:"Six", 7:"Seven", 8:"Eight", 9:"Nine", 10:"Ten", 11:"Jack", 12:"Queen", 13:"King", 14:"Ace"}
        for value in values:
            for suit in suits:
                self.append(Card(values[value],suit))
        random.shuffle(self)

    #picks a card from the deck
    def getCard(self):
        return self.pop(0)


#tables' class
class Table(object):
    #initializes with user-defined seats and no-players
    def __init__(self,seats):
        self.seats = seats
        self.cards = []
        self.users = []
        self.inGame = False
        for i in range(seats):
            self.users.append(None)

    def __repr__(self):
        return "A table of " + str(self.seats) + " people."

    def addUser(self,seat,player,chips):
        self.users[seat] = player,chips
        count = 0
        currentPlayers = []
        for i in range(len(self.users)):
            if self.users[i] != None:
                user,a = self.users[i]
                count+=1
                currentPlayers.append(user)
                print(currentPlayers)
        if count > 1 and self.inGame == False:
            self.inGame = True
            self.game = Game(currentPlayers,RandomDeck())
        elif count > 1 and self.inGame == True:
            sendMessage(socket,player.username,"Wait for a new game")


class Player(object):
    def __init__(self,username,chips):
        self.username = username
        self.chips = chips
        self.currentChips = 0
        self.cards = []
        self.table = None
        self.gaveAmount = 0
        self.rank = 0
        self.highest = 0

    def giveCard(self,number,deck):
        for i in range(number):
            self.cards.append(deck.getCard())

    def joinTable(self,table,choice,chipsNumber):
        if self.table==None:
            if table.users[choice] == None:
                if chipsNumber <= self.chips:
                    table.addUser(choice,self,chipsNumber)
                    self.currentChips = chipsNumber
                    self.table = table
                    sendMessage(socket,self.username,"Successfully reserved your seat")
                else:
                    sendMessage(socket,self.username,"Sorry, you have only "+ str(self.chips)+ " chips")
            else:
                sendMessage(socket,self.username,"Sorry, this seat is reserved, choose other place.")
        else:
            sendMessage(socket,self.username,"You are already sitting on " + self.table)

    def leaveTable(self):
        if self.table!=None:
            table = self.table
            for i in table.users:
                if i == self.username:
                    table.users[i] = None
            sendMessage(socket,self.username,"You escaped the table.")
            self.table = None
        else:
            sendMessage(socket,self.username,"You are not sitting.")


def createTable():
    tables.append(Table(5))

def checkForSequence(a):
    print(a)
    for i in range(4):
        if a[i]+1 != a[i+1]:
            return False
    return True

class Game(object):
    def __init__(self,players,cards):
        deck = RandomDeck()
        self.bank = 0
        self.center = []
        self.turn = 1
        self.isBetting = False
        self.betted = []
        for i in range(5):
            self.center.append(deck.getCard())
        self.players = []
        for player in players:
            player.giveCard(2,cards)
            player.gaveAmount = 0
            player.rank = 0
            self.players.append(player)
            myCards = player.cards
            for i in range(len(myCards)):
                myCards[i].visible = True
            cardString = str(myCards[0])+" and "+str(myCards[1])
            sendMessage(socket,player.username,"Your cards are " + cardString)
        self.i = 0
        self.giveChoice(self.players[self.i])
        self.currentMover = self.players[self.i].username

    def isFlush(self,playerCards):
        counter = {}
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        for card in playerCards:
            if card.suit not in counter:
                counter[card.suit] = 1
            else:
                counter[card.suit] += 1
        cards = []
        for theSuit in counter:
            if counter[theSuit]>4:
                cards = []
                for value in playerCards:
                    if card.suit == theSuit:
                        cards.append(card.value)
        if len(cards)>4:
            if len(cards)==5:
                return [True,cards[0]]
            elif len(cards)>5:
                return [True,cards[-1]]
        return [False]
                        
        



                
    def isStreet(self,playerCards):
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        uniqueCards = []
        for card in playerCards:
            if values[card.value] not in uniqueCards:
                uniqueCards.append(values[card.value])
                if card.value == "Ace":
                    uniqueCards.append(1)
        print(uniqueCards)
        uniqueCards.sort()
        if len(uniqueCards) < 5:
            return False
        street = []
        for i in range(len(uniqueCards)-4):
            if checkForSequence(uniqueCards[i:i+5]) == True:
                street.append(uniqueCards[i+4])
        if len(street)>0:
            if len(street)==1:
                return [True,street[0]]
            elif len(street)>1:
                return [True,street[-1]]
        return [False]



    def isPair(self,playerCards):
        counter = {}
        for card in playerCards:
            if card.value not in counter:
                counter[card.value] = 1
            else:
                counter[card.value] += 1
        pairs = []
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        for value in counter:
            if counter[value] == 2:
                pairs.append(values[value])
        if len(pairs)>0:
            if len(pairs)==1:
                return [True,1,pairs[0]]
            elif len(pairs)>1:
                return [True,2,pairs[-1],pairs[-2]]
        return [False]
                

    def isThree(self,playerCards):
        counter = {}
        for card in playerCards:
            if card.value not in counter:
                counter[card.value] = 1
            else:
                counter[card.value] += 1
        three = []
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        for value in counter:
            if counter[value] == 3:
                three.append(values[value])
        if len(three)>0:
            a = max(three)
            return [True,a]
        return [False]
        
    def isFour(self,playerCards):
        counter = {}
        for card in playerCards:
            if card.value not in counter:
                counter[card.value] = 1
            else:
                counter[card.value] += 1
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        for value in counter:
            if counter[value] == 4:
                return [True,values[value]]
        return [False]

    def highest(self,allCards):
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        uniqueCards = []
        for card in allCards:
            if values[card.value] not in uniqueCards:
                uniqueCards.append(values[card.value])
        return uniqueCards[-1]


    def checkWinner(self):
        if len(self.players)==1:
            self.players[0].chipsNumber += self.bank
            self.players[0].currentChips += self.bank
        else:
            rankings = []
            for player in self.players:
                player.highest = 0
                player.rank = 0
                allCards = player.cards+self.center
                print(allCards)
                values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
                allCards = sorted(allCards, key=lambda x: values[x.value])
                print(allCards)
                if self.isFlush(allCards)[0] and self.isStreet(allCards)[0]:
                    if self.isStreet(allCards)[1]==14:
                        player.rank = 10
                    player.rank = 9
                    player.highest = self.isStreet(allCards)[1]
                elif self.isFour(allCards):
                    player.rank = 8
                elif self.isThree(allCards)[0] and self.isPair(allCards)[0] and (self.isThree(allCards)[1]!=self.isPair(allCards)[1] or self.isThree(allCards)[1]!=self.isPair(allCards)[2]):
                    player.rank = 7
                    if self.isThree(allCards)[1]>self.isPair(allCards)[1]:
                        player.highest = self.isThree(allCards)[1]
                    else:
                        player.highest = self.isPair(allCards)[1]
                elif self.isFlush(allCards)[0]:
                    player.rank = 6
                    player.highest = self.isFlush(allCards)[1]
                elif self.isStreet(allCards)[0]:
                    player.rank = 5
                    player.highest = self.isStreet(allCards)[1]
                elif self.isThree(allCards)[0]:
                    player.rank = 4
                    player.highest = self.isThree(allCards)[1]
                elif self.isPair(allCards) and len(self.isPair(allCards))==3:
                    player.rank = 3
                    player.highest = self.isPair(allCards)[1]
                elif self.isPair(allCards):
                    player.rank = 2
                    player.highest = self.isPair(allCards)[1]
                else:
                    player.rank = 1
                    player.highest = self.highest(allCards)
                rankings.append((player.rank,player.highest,player.username))
                print(self.isFlush(allCards)[0])
                print(self.isStreet(allCards)[0])
                print(self.isPair(allCards)[0])
                print(self.isThree(allCards)[0])
                print(self.isFour(allCards)[0])
                print(self.isPair(allCards)[0] and self.isThree(allCards)[0])
                print(self.highest(allCards))
            rankings.sort(key=lambda tup:tup[0])
            highest_rank,card,username = rankings[0]
            print(highest_rank + "IS HIGHEST RANK")
            count = 0
            cards = [(card,username)]
            if len(rankings)>1:
                for (r,c,u) in rankings[1:]:
                    if highest_rank==r:
                        cards.append((c,u))
            cards.sort(key=lambda tup:tup[0])
            highest_card,username = cards[0]
            winners = [username]
            if len(cards)>1:
                for (c,u) in cards[1:]:
                    if highest_card==c:
                        winners.append(u)
            print(winners)
            number = len(winners)
            for gamer in self.players:
                if gamer.username in winners:
                    sendMessage(socket,gamer.username,"You won")
            
            




    def giveChoice(self,player):
        sendMessage(socket,player.username,"Choose to Check/Fold/Bet/Call/Raise")

    def check(self,player):
        if self.isBetting == False:
            for gamer in self.players:
                sendMessage(socket,gamer.username,str(player) + " have checked")
            self.i += 1
            if len(self.players) == 1:
                self.checkWinner()
            elif self.i != len(self.players):
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
            elif self.turn != 4:
                for gamer in self.players:
                    sendMessage(socket,gamer.username,"Central cards are: ")
                    if self.turn == 1:
                        self.center[0].visible = True
                        self.center[1].visible = True
                        self.center[2].visible = True
                        sendMessage(socket,gamer.username,str(self.center[0]))
                        sendMessage(socket,gamer.username,str(self.center[1]))
                        sendMessage(socket,gamer.username,str(self.center[2]))
                    else:
                        self.center[self.turn+1].visible = True
                        sendMessage(socket,gamer.username,str(self.center[self.turn+1]))
                self.turn += 1
                self.i = 0
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
            else:
                self.checkWinner()
        else:
            if playerlist[player].currentChips < self.betAmount:
                amount = playerlist[player].currentChips
            else:
                amount = self.betAmount
            playerlist[player].currentChips -= amount
            playerlist[player].chips -= amount
            playerlist[player].gaveAmount += amount
            self.bank += amount
            self.betted.append(player)
            for gamer in self.players:
                sendMessage(socket,gamer.username,str(player) + " is calling " + str(amount))
            self.i += 1
            if len(self.betted)!=len(self.players):
                if self.i==len(self.players):
                    self.i = 0
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
            else:
                self.isBetting = False
                if len(self.players) == 1:
                    self.checkWinner()
                elif self.i != len(self.players):
                    self.giveChoice(self.players[self.i])
                    self.currentMover = self.players[self.i].username
                elif self.turn != 4:
                    for gamer in self.players:
                        sendMessage(socket,gamer.username,"Central cards are: ")
                        if self.turn == 1:
                            self.center[0].visible = True
                            self.center[1].visible = True
                            self.center[2].visible = True
                            sendMessage(socket,gamer.username,str(self.center[0]))
                            sendMessage(socket,gamer.username,str(self.center[1]))
                            sendMessage(socket,gamer.username,str(self.center[2]))
                        else:
                            self.center[self.turn+1].visible = True
                            sendMessage(socket,gamer.username,str(self.center[self.turn+1]))
                    self.turn += 1
                    self.i = 0
                    self.giveChoice(self.players[self.i])
                    self.currentMover = self.players[self.i].username
                else:
                    self.checkWinner()
        print(self.bank)

    def bet(self,player,amount):
        if self.isBetting == False:
            if amount <= playerlist[player].currentChips:
                self.isBetting = True
                self.betAmount = amount
                for gamer in self.players:
                    sendMessage(socket,gamer.username,str(player) + " have bet" + str(amount))
                playerlist[player].currentChips -= amount
                playerlist[player].chips -= amount
                playerlist[player].gaveAmount += amount
                self.bank += amount
                self.betted = [player]
                self.i += 1
                if len(self.betted)!=len(self.players):
                    if self.i==len(self.players):
                        self.i = 0
                    self.giveChoice(self.players[self.i])
                    self.currentMover = self.players[self.i].username
                else:
                    self.isBetting = False
                    if len(self.players) == 1:
                        self.checkWinner()
                    elif self.i != len(self.players):
                        self.giveChoice(self.players[self.i])
                        self.currentMover = self.players[self.i].username
                    elif self.turn != 4 and len(self.players):
                        for gamer in self.players:
                            sendMessage(socket,gamer.username,"Central cards are: ")
                            if self.turn == 1:
                                self.center[0].visible = True
                                self.center[1].visible = True
                                self.center[2].visible = True
                                sendMessage(socket,gamer.username,str(self.center[0]))
                                sendMessage(socket,gamer.username,str(self.center[1]))
                                sendMessage(socket,gamer.username,str(self.center[2]))
                            else:
                                self.center[self.turn+1].visible = True
                                sendMessage(socket,gamer.username,str(self.center[self.turn+1]))
                        self.turn += 1
                        self.i = 0
                        self.giveChoice(self.players[self.i])
                        self.currentMover = self.players[self.i].username
                    else:
                        self.checkWinner()
            else:
                sendMessage(socket,player,"You have not enough chips")
                self.giveChoice(self.players[self.i])
        else:
            if amount+self.betAmount <= playerlist[player].currentChips:
                self.betAmount = amount+self.betAmount
                for gamer in self.players:
                    sendMessage(socket,gamer.username,str(gamer.username) + " have raised" + str(amount))
                playerlist[player].currentChips -= self.betAmount
                playerlist[player].chips -= self.betAmount
                self.bank += self.betAmount
                playerlist[player].gaveAmount += playerlist[player].gaveAmount + self.betAmount
                self.betted = [player]
                self.i += 1
                if self.i != len(self.players):
                    self.giveChoice(self.players[self.i])
                    self.currentMover = self.players[self.i].username
                else:
                    self.isBetting = False
                    if len(self.players) == 1:
                        self.checkWinner()
                    elif self.turn != 4 and len(self.players):
                        for gamer in self.players:
                            sendMessage(socket,gamer.username,"Central cards are: ")
                            if self.turn == 1:
                                self.center[0].visible = True
                                self.center[1].visible = True
                                self.center[2].visible = True
                                sendMessage(socket,gamer.username,str(self.center[0]))
                                sendMessage(socket,gamer.username,str(self.center[1]))
                                sendMessage(socket,gamer.username,str(self.center[2]))
                            else:
                                self.center[self.turn+1].visible = True
                                sendMessage(socket,gamer.username,str(self.center[self.turn+1]))
                        self.turn += 1
                        self.i = 0
                        self.giveChoice(self.players[self.i])
                        self.currentMover = self.players[self.i].username
                    else:
                        self.checkWinner()
            else:
                sendMessage(socket,player.username,"You have not enough chips")
                self.giveChoice(self.players[self.i])
        print(self.bank)



    def fold(self,player):
        for gamer in self.players:
            sendMessage(socket,gamer.username,str(player.username) + " have fold")
        playerlist[player].cards = None
        self.players.remove(player)
        if self.isBetting == True:
            if len(self.betted)!=len(self.players):
                if self.i==len(self.players):
                    self.i = 0
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
            else:
                if len(self.players) == 1:
                    self.checkWinner()
                elif self.i != len(self.players):
                    self.giveChoice(self.players[self.i])
                    self.currentMover = self.players[self.i].username
                elif self.turn != 4:
                    for gamer in self.players:
                        sendMessage(socket,gamer.username,"Central cards are: ")
                        if self.turn == 1:
                            self.center[0].visible = True
                            self.center[1].visible = True
                            self.center[2].visible = True
                            sendMessage(socket,gamer.username,str(self.center[0]))
                            sendMessage(socket,gamer.username,str(self.center[1]))
                            sendMessage(socket,gamer.username,str(self.center[2]))
                        else:
                            self.center[self.turn+1].visible = True
                            sendMessage(socket,gamer.username,str(self.center[self.turn+1]))
                    self.turn += 1
                    self.i = 0
                    self.giveChoice(self.players[self.i])
                    self.currentMover = self.players[self.i].username
                else:
                    self.checkWinner()
        else:
            if len(self.players) == 1:
                self.checkWinner()
            elif self.i != len(self.players):
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
            elif self.turn != 4:
                for gamer in self.players:
                    sendMessage(socket,gamer.username,"Central cards are: ")
                    if self.turn == 1:
                        self.center[0].visible = True
                        self.center[1].visible = True
                        self.center[2].visible = True
                        sendMessage(socket,gamer.username,str(self.center[0]))
                        sendMessage(socket,gamer.username,str(self.center[1]))
                        sendMessage(socket,gamer.username,str(self.center[2]))
                    else:
                        self.center[self.turn+1].visible = True
                        sendMessage(socket,gamer.username,str(self.center[self.turn+1]))
                self.turn += 1
                self.i = 0
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
            else:
                self.checkWinner()
        print(self.bank)


class startWnd():
    def __init__(self,root):
        self.root = root
        self.mainFrame = tkinter.Frame(root)
        self.mainFrame.pack()
        self.mainFrame.after(500,self.update)

    #This should automatically create tables by checking every second(OOP side)
    def update(self):
        receiveCommands(socket)
        if len(players)-1 != len(tables) and len(players) != 0:
            createTable()
        self.mainFrame.after(500,self.update)





def userJoined(s,u,playerlist,players):
    print(players,playerlist)
    if u in players:
        sendMessage(s,u,"You are already registered, " + u + " . \n Now you have " + str(playerlist[u].chips) + " poker chips.")
    else:
        print("wants to join")
        players.append(u)
        playerlist[u] = Player(u,50000)
        print(players,playerlist)
        if sendMessage(s,u,"Welcome in our hidden casino, " + u + " \nFor joining, we are giving you "+ str(playerlist[u].chips) + " poker chips. \nIf you want more, buy offline from nzekenov with price: 500 chips for 100 riyals."):
            print("Sent message")

#this returns client the list of tables
def returnTables(tableList,u):
    message = "/"+str(len(tableList))
    for i in range(len(tableList)):
        message += "/" + str(i)+"/"+str(tableList[i])
    sendMessage(socket,u,message)

#this function should update every second and check for new messages from users
def receiveCommands(s):
    (Messages, Files) = getMail(s)
    print(Messages)
    if Messages != []:
        for (u, m) in Messages:
            if m != " ":
                command = m.split("/")
                print(command[0])
                if command[0] == "":
                    print(command[1])
                    if command[1] == "play":
                        print(u + " Wants to play")
                        userJoined(s,u,playerlist,players)
                    elif command[1] == "tables":
                        if u in players:
                            returnTables(tables,u)
                        else:
                            sendMessage(s,u,"You are not registered in game, please send '/play' to register")
                    elif command[1] == "join":
                        if u in players:
                            playerlist[u].joinTable(tables[int(command[2])],int(command[3]),int(command[4]))
                            print(tables[int(command[2])].users)
                        else:
                            sendMessage(s,u,"You are not registered in game, please send '/play' to register")
                    elif command[1] == "leave":
                        if u in players:
                            if playerlist[u].table != None:
                                playerlist[u].leaveTable()
                        else:
                            sendMessage(s,u,"You are not registered in game, please send '/play' to register")
                    elif command[1] == "check":
                        if u in players:
                            if playerlist[u].table != None:
                                if playerlist[u].table.inGame == True:
                                    if playerlist[u] in playerlist[u].table.game.players:
                                        if u == playerlist[u].table.game.currentMover:
                                            #should check whether his step
                                            playerlist[u].table.game.check(u)
                                        else:
                                            sendMessage(s,u,"It is not your turn")
                                    else:
                                        sendMessage(s,u,"You are not currently playing")
                                else:
                                    sendMessage(s,u,"Your table is not currently playing")
                            else:
                                sendMessage(s,u,"You have to sit on table to play")
                        else:
                            sendMessage(s,u,"You are not registered in game, please send '/play' to register")
                    elif command[1] == "bet":
                        if u in players:
                            if playerlist[u].table != None:
                                if playerlist[u].table.inGame == True:
                                    if playerlist[u] in playerlist[u].table.game.players:
                                        if u == playerlist[u].table.game.currentMover:
                                            #should check whether his step
                                            playerlist[u].table.game.bet(u,int(command[2]))
                                        else:
                                            sendMessage(s,u,"It is not your turn")
                                    else:
                                        sendMessage(s,u,"You are not currently playing")
                                else:
                                    sendMessage(s,u,"Your table is not currently playing")
                            else:
                                sendMessage(s,u,"You have to sit on table to play")
                        else:
                            sendMessage(s,u,"You are not registered in game, please send '/play' to register")
                    elif command[1] == "fold":
                        if u in players:
                            if playerlist[u].table != None:
                                if playerlist[u].table.inGame == True:
                                    if playerlist[u] in playerlist[u].table.game.players:
                                        if u == playerlist[u].table.game.currentMover:
                                            #should check whether his step
                                            playerlist[u].table.game.fold(u)
                                        else:
                                            sendMessage(s,u,"It is not your turn")
                                    else:
                                        sendMessage(s,u,"You are not currently playing")
                                else:
                                    sendMessage(s,u,"Your table is not currently playing")
                            else:
                                sendMessage(s,u,"You have to sit on table to play")
                        else:
                            sendMessage(s,u,"You are not registered in game, please send '/play' to register")
                    else:
                        sendMessage(s,u,"Undefined command")




socket = StartConnection("86.36.46.10", 15112)
while not login (socket, "nzekenov", "nzekenov"):
    print ("Something went wrong, but it's not ur fault")
print("Your program is setted up")
players = []
playerlist = {}
tables = []
wnd = tkinter.Tk()
wnd.title("Dealer")
dealerApp = startWnd(wnd)
wnd.mainloop()
