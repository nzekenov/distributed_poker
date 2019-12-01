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
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":"J", "Queen":"Q", "King":"Q", "Ace":"A"}
        if self.visible == True:
            return "/" + str(values[(self.value)]) + "/" + str(self.suit)
        return "Card"

#RandomDeck
class RandomDeck(list):
    #initializes a list of random cards with 52 elements
    def __init__(self):
        suits = ["S", "H", "D", "C"]
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
    #initializes with user-defined seats and no-players and id
    def __init__(self,seats,id):
        self.seats = seats
        self.cards = []
        self.id = id
        self.users = []
        self.inGame = False
        for i in range(seats):
            self.users.append(None)

    #show the number of empty places
    def __repr__(self):
        empty = 0
        for i in self.users:
            if i == None:
                empty += 1
        return "/"+str(empty)

    #adds user to table's users
    def addUser(self,player):
        i = 0
        while self.users[i]!=None:
            i+=1
        self.users[i] = playerlist[player]
        print(self.users)
        count = 0
        currentPlayers = []
        for i in range(len(self.users)):
            if self.users[i] != None:
                user = self.users[i]
                count+=1
                currentPlayers.append(user)
                sendMessage(socket,user.username,"/game")
        print(currentPlayers)
        if count > 1 and self.inGame == False:
            self.inGame = True
            self.game = Game(currentPlayers,RandomDeck())
        elif count > 1 and self.inGame == True:
            sendMessage(socket,player.username,"/wait")


#players' class
class Player(object):
    #initializes player with username,chips, and attributes for a game
    def __init__(self,username,chips):
        self.username = username
        self.chips = chips
        self.currentChips = 0
        self.cards = []
        self.table = None
        self.gaveAmount = 0
        self.rank = 0
        self.highest = 0


    def __repr__(self):
        return "/"+str(self.username)+"/"+str(self.chips)

    #gives a card from the deck of game
    def giveCard(self,number,deck):
        for i in range(number):
            self.cards.append(deck.getCard())

    #adds user to specific table, seat and chosen amount of chips
    def joinTable(self,table,chipsNumber):
        #if everything done successfully, returns OK, otherwise, show the type of error
        if self.table==None:
            if chipsNumber <= self.chips:
                counter = 0
                for user in table.users:
                    if user != None:
                        counter += 1
                if counter <5:
                    sendMessage(socket,self.username,"/ok/joinTable")
                    table.addUser(self.username)
                    self.currentChips = chipsNumber
                    self.table = table
                else:
                    sendMessage(socket,self.username,"/no/full")
            else:
                sendMessage(socket,self.username,"/no/chips/"+ str(self.chips))
        else:
            sendMessage(socket,self.username,"/no/already_othertable")

    #remove user from the table
    def leaveTable(self):
        if self.table!=None:
            table = self.table
            for i in table.users:
                if i == self.username:
                    table.users[i] = None
            sendMessage(socket,self.username,"/leave")
            self.table = None
        else:
            sendMessage(socket,self.username,"/no")

    def sendPlayers(self):
        if self.table!=None:
            table = self.table
            users = ""
            count = 0
            for i in range(len(table.users)):
                if table.users[i]!= None:
                    users += "/"+str(table.users[i].username)+"/"+str(table.users[i].currentChips)
                    count += 1
            print(users)
            print(self.username)
            sendMessage(socket,self.username,"/players/"+str(count)+users)
        else:
            sendMessage(socket,self.username,"/no/not_sitting")

#create a new table
def createTable():
    id = len(tables)
    tables.append(Table(5,id))

#sequence checker
def checkForSequence(a):
    print(a)
    #if non-consecutive numbers identified, returns False
    for i in range(4):
        if a[i]+1 != a[i+1]:
            return False
    return True

#games' class
class Game(object):
    def __init__(self,players,cards):
        #game is initialized with players,randomdeck
        deck = RandomDeck()
        self.bank = 0
        self.center = []
        self.turn = 1
        self.isBetting = False
        self.betted = []
        #get 5 random cards from the deck
        for i in range(5):
            self.center.append(deck.getCard())
        self.players = []
        print("-->> ARE PLAYERS")
        print(players)
        #give each player 2 cards and send them in messages
        for player in players:
            player.giveCard(2,cards)
            sendMessage(socket,player.username,"/game")
            player.gaveAmount = 0
            player.rank = 0
            self.players.append(player)
            myCards = player.cards
            for i in range(len(myCards)):
                myCards[i].visible = True
            cardString = str(myCards[0])+str(myCards[1])
            sendMessage(socket,player.username,"/cards/your" + cardString)
        #start a game from the first person
        self.i = 0
        self.giveChoice(self.players[self.i])
        self.currentMover = self.players[self.i].username

    #flush combination in poker identify if 5 or more cards are of same suit
    #if yes, return the highest card of the suit and True
    def isFlush(self,playerCards):
        #counts number of cards for each suit
        counter = {}
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        for card in playerCards:
            if card.suit not in counter:
                counter[card.suit] = 1
            else:
                counter[card.suit] += 1
        cards = []
        #if suit have more than 4 cards, adds all cards of the suit to the list
        for theSuit in counter:
            if counter[theSuit]>4:
                cards = []
                for value in playerCards:
                    if card.suit == theSuit:
                        cards.append(card.value)
        #find the maximum card and return the result
        if len(cards)>4:
            if len(cards)==5:
                return [True,cards[0]]
            elif len(cards)>5:
                return [True,cards[-1]]
        return [False]





    #checks for street combination (5 consecutive cards (e.g 2,3,4,5,6) in the table)
    def isStreet(self,playerCards):
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        uniqueCards = []
        #gets all unique cards
        for card in playerCards:
            if values[card.value] not in uniqueCards:
                uniqueCards.append(values[card.value])
                if card.value == "Ace":
                    uniqueCards.append(1)
        print(uniqueCards)
        #puts cards in order
        uniqueCards.sort()
        #if the length of the new list is less than 5, return False
        if len(uniqueCards) < 5:
            return False
        street = []
        #checks for the sequences in each of the subsets if 5 values
        for i in range(len(uniqueCards)-4):
            if checkForSequence(uniqueCards[i:i+5]) == True:
                street.append(uniqueCards[i+4])
        if len(street)>0:
            if len(street)==1:
                return [True,street[0]]
            elif len(street)>1:
                return [True,street[-1]]
        return [False]


    #checks for pairs in cards on table
    def isPair(self,playerCards):
        #count number of each card value
        counter = {}
        for card in playerCards:
            if card.value not in counter:
                counter[card.value] = 1
            else:
                counter[card.value] += 1
        pairs = []
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        #if value appeared twice, add to pairs' list
        for value in counter:
            if counter[value] == 2:
                pairs.append(values[value])
        #find highest pair
        #find highest two pairs
        if len(pairs)>0:
            if len(pairs)==1:
                return [True,pairs[-1]]
            elif len(pairs)>1:
                return [True,pairs[-1],pairs[-2]]
        return [False]

    #checks for the combination of three of the same values
    def isThree(self,playerCards):
        counter = {}
        #counts apperance of each card value
        for card in playerCards:
            if card.value not in counter:
                counter[card.value] = 1
            else:
                counter[card.value] += 1
        three = []
        #checks for values appeared three times in stack
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        for value in counter:
            if counter[value] == 3:
                three.append(values[value])
        #returns highest value of appeared triple times card
        if len(three)>0:
            a = max(three)
            return [True,a]
        return [False]

    #checks for the combination of four of the same values
    def isFour(self,playerCards):
        counter = {}
        #counts apperance of each card value
        for card in playerCards:
            if card.value not in counter:
                counter[card.value] = 1
            else:
                counter[card.value] += 1
         #checks for values appeared four times in stack
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        for value in counter:
            #returns value of appeared four times card
            if counter[value] == 4:
                return [True,values[value]]
        return [False]

    #returns highest card value in the stack
    def highest(self,allCards):
        values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
        uniqueCards = []
        for card in allCards:
            if values[card.value] not in uniqueCards:
                uniqueCards.append(values[card.value])
        #find the unique cards, and return highest among them
        return uniqueCards[-1]

    #method for identifying a winner
    def checkWinner(self):
        #if one player left, he is winner
        if len(self.players)==1:
            winners = [self.players[0].username]
        else:
        #otherwise, check for combinations of each player and make ranknings
            rankings = []
            for player in self.players:
                player.highest = 0
                player.rank = 0
                allCards = player.cards+self.center
                print(allCards)
                values = {"Two":2, "Three":3, "Four":4, "Five":5, "Six":6, "Seven":7, "Eight":8, "Nine":9, "Ten":10, "Jack":11, "Queen":12, "King":13, "Ace":14}
                allCards = sorted(allCards, key=lambda x: values[x.value])
                print(allCards)
                #Royal FLUSH or Street Flush Combination (Highest 5/ Any 5 consecutive cards of the same suit)
                if self.isFlush(allCards)[0] and self.isStreet(allCards)[0]:
                    if self.isStreet(allCards)[1]==14:
                        player.rank = 10
                    player.rank = 9
                    player.highest = self.isStreet(allCards)[1]
                #four of same values
                elif self.isFour(allCards)[0]:
                    player.rank = 8
                    player.highest = self.isFour(allCards)[1]
                #Full House (3 & 2 same valued cards)
                elif self.isThree(allCards)[0] and self.isPair(allCards)[0] and (self.isThree(allCards)[1]!=self.isPair(allCards)[1] or self.isThree(allCards)[1]!=self.isPair(allCards)[2]):
                    player.rank = 7
                    if self.isThree(allCards)[1]>self.isPair(allCards)[1]:
                        player.highest = self.isThree(allCards)[1]
                    else:
                        player.highest = self.isPair(allCards)[1]
                #Flush (>4 cards of the same suit)
                elif self.isFlush(allCards)[0]:
                    player.rank = 6
                    player.highest = self.isFlush(allCards)[1]
                #Street (>4 cards consecutive)
                elif self.isStreet(allCards)[0]:
                    player.rank = 5
                    player.highest = self.isStreet(allCards)[1]
                #Three of same values
                elif self.isThree(allCards)[0]:
                    player.rank = 4
                    player.highest = self.isThree(allCards)[1]
                #Two pairs of cards
                elif self.isPair(allCards)[0] and len(self.isPair(allCards))==3:
                    player.rank = 3
                    player.highest = self.isPair(allCards)[1]
                #One pair
                elif self.isPair(allCards):
                    player.rank = 2
                    player.highest = self.isPair(allCards)[1]
                #highest card
                else:
                    player.rank = 1
                    player.highest = self.highest(allCards)
                print(player.rank)
                print(player.highest)
                rankings.append((player.rank,player.highest,player.username))
            rankings.sort(key=lambda tup:tup[0])
            highest_rank,card,username = rankings[0]
            print(rankings)
            print(str(highest_rank) + "IS HIGHEST RANK")
            count = 0
            cards = [(card,username)]
            #identify users with highest rank
            if len(rankings)>1:
                for (r,c,u) in rankings[1:]:
                    if highest_rank==r:
                        cards.append((c,u))
            print(cards)
            cards.sort(key=lambda tup:tup[0])
            highest_card,username = cards[0]
            winners = [username]
            #identify users with highest card in the rank
            if len(cards)>1:
                for (c,u) in cards[1:]:
                    if highest_card==c:
                        winners.append(u)
            #those users are winners
        print(winners)
        number = len(winners)
        winamount = self.bank//number
        for gamer in self.players:
            if gamer.username in winners:
                gamer.currentChips += winamount
                gamer.chips += winamount
                sendMessage(socket,gamer.username,"/won/"+str(winamount))
            sendMessage(socket,gamer.username,"/end")





    #send message with a choice
    def giveChoice(self,player):
        print("SENDING"+player.username)
        sendMessage(socket,player.username,"/move/"+str(self.bank))

    #if player is checking or calling
    def check(self,player):
        #identify whether he can check or call
        if self.isBetting == False:
            #if he can check, next person should move
            for gamer in self.players:
                sendMessage(socket,gamer.username,"/check/"+str(player))
            self.i += 1
            #check if number of users is more than 1
            if len(self.players) == 1:
                #if not, he won
                self.checkWinner()
            #check if he is the last person in the queve
            elif self.i != len(self.players):
                #if not, then next person moves
                print(self.players)
                print(self.i)
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
                print("I SENT" + str(self.players[self.i]))
            elif self.turn != 4:
                #if it is the end of current turn show central cards
                for gamer in self.players:
                    if self.turn == 1:
                        self.center[0].visible = True
                        self.center[1].visible = True
                        self.center[2].visible = True
                        sendMessage(socket,gamer.username,"/cards/center"+str(self.center[0])+str(self.center[1])+str(self.center[2]))
                    else:
                        self.center[self.turn+1].visible = True
                        sendMessage(socket,gamer.username,"/cards/center"+str(self.center[self.turn+1]))
                #increment the turns' number and start moving the first player
                self.turn += 1
                self.i = 0
                print(self.players)
                print(self.i)
                self.giveChoice(self.players[self.i])
                self.currentMover = self.players[self.i].username
                print("I SENT" + str(self.players[self.i]))
            else:
                self.checkWinner()
        else:
            #if the turn is betting
            #user calls the betted amount, but if it is more, gives all his chips, not more
            if playerlist[player].currentChips < self.betAmount:
                amount = playerlist[player].currentChips
            else:
                amount = self.betAmount
            #amount will be added to table's bank, and removed from player's bank
            playerlist[player].currentChips -= amount
            playerlist[player].chips -= amount
            playerlist[player].gaveAmount += amount
            self.bank += amount
            self.betted.append(player)
            for gamer in self.players:
                sendMessage(socket,gamer.username,"/call/"+str(amount)+"/"+str(player))
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
                        if self.turn == 1:
                            self.center[0].visible = True
                            self.center[1].visible = True
                            self.center[2].visible = True
                            sendMessage(socket,gamer.username,"/cards/center"+str(self.center[0])+str(self.center[1])+str(self.center[2]))
                        else:
                            self.center[self.turn+1].visible = True
                            sendMessage(socket,gamer.username,"/cards/center"+str(self.center[self.turn+1]))
                    self.turn += 1
                    self.i = 0
                    self.giveChoice(self.players[self.i])
                    self.currentMover = self.players[self.i].username
                else:
                    self.checkWinner()
        print(self.bank)

    def bet(self,player,amount):
        #identify whether it is betting or raising
        #if betting
        if self.isBetting == False:
            #check if user have enough chips to bet
            if amount <= playerlist[player].currentChips:
                #if yes, table is currently betting
                self.isBetting = True
                #betAmount is equal to number of chips given by player
                self.betAmount = amount
                for gamer in self.players:
                    sendMessage(socket,gamer.username,"/bet/" + str(amount) + "/" + str(player))
                #add the amount to table's bank and remove from player's bank
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
                            if self.turn == 1:
                                self.center[0].visible = True
                                self.center[1].visible = True
                                self.center[2].visible = True
                                sendMessage(socket,gamer.username,"/cards/center"+str(self.center[0])+str(self.center[1])+str(self.center[2]))
                            else:
                                self.center[self.turn+1].visible = True
                                sendMessage(socket,gamer.username,"/cards/center"+str(self.center[self.turn+1]))
                        self.turn += 1
                        self.i = 0
                        self.giveChoice(self.players[self.i])
                        self.currentMover = self.players[self.i].username
                    else:
                        self.checkWinner()
            else:
                sendMessage(socket,player,"/no/not_enough")
                self.giveChoice(self.players[self.i])
        else:
            if amount+self.betAmount <= playerlist[player].currentChips:
                self.betAmount = amount+self.betAmount
                for gamer in self.players:
                    sendMessage(socket,gamer.username,"/raise/"+str(amount)+"/"+str(gamer.username))
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
                            if self.turn == 1:
                                self.center[0].visible = True
                                self.center[1].visible = True
                                self.center[2].visible = True
                                sendMessage(socket,gamer.username,"/cards/center"+str(self.center[0])+str(self.center[1])+str(self.center[2]))
                            else:
                                self.center[self.turn+1].visible = True
                                sendMessage(socket,gamer.username,"/cards/center"+str(self.center[self.turn+1]))
                        self.turn += 1
                        self.i = 0
                        self.giveChoice(self.players[self.i])
                        self.currentMover = self.players[self.i].username
                    else:
                        self.checkWinner()
            else:
                sendMessage(socket,player.username,"/no/not_enough")
                self.giveChoice(self.players[self.i])
        print(self.bank)



    def fold(self,player):
        for gamer in self.players:
            sendMessage(socket,gamer.username,"/fold/"+str(player.username))
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
                        if self.turn == 1:
                            self.center[0].visible = True
                            self.center[1].visible = True
                            self.center[2].visible = True
                            sendMessage(socket,gamer.username,"/cards/center"+str(self.center[0])+str(self.center[1])+str(self.center[2]))
                        else:
                            self.center[self.turn+1].visible = True
                            sendMessage(socket,gamer.username,"/cards/center"+str(self.center[self.turn+1]))
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
                    if self.turn == 1:
                        self.center[0].visible = True
                        self.center[1].visible = True
                        self.center[2].visible = True
                        sendMessage(socket,gamer.username,"/cards/center"+str(self.center[0])+str(self.center[1])+str(self.center[2]))
                    else:
                        self.center[self.turn+1].visible = True
                        sendMessage(socket,gamer.username,"/cards/center"+str(self.center[self.turn+1]))
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
        self.mainFrame.after(50,self.update)

    #This should automatically create tables by checking every second(OOP side) and get commands from players
    def update(self):
        receiveCommands(socket)
        if len(players)-1 != len(tables) and len(players) != 0:
            createTable()
        self.mainFrame.after(50,self.update)



def userJoined(s,u,playerlist,players):
    print(players,playerlist)
    if u in players:
        sendMessage(s,u,"/back/" + u + "/" + str(playerlist[u].chips))
    else:
        players.append(u)
        playerlist[u] = Player(u,50000)
        if sendMessage(s,u,"/welcome/" + u + "/"+ str(playerlist[u].chips)):
            print("Sent message to " + u)

#this returns client the list of tables
def returnTables(tableList,u):
    message = "/tables/"+str(len(tableList))
    for i in range(len(tableList)):
        message += "/" + str(i)+str(tableList[i])
    sendMessage(socket,u,message)

#this function should update every second and check for new requests from users
def receiveCommands(s):
    (Messages, Files) = getMail(s)
    print(Messages)
    #depending on the request from user, returns the result (SUCCESS/FAIL) or does a function
    if Messages != []:
        for (u, m) in Messages:
            if m != " ":
                command = m.split("/")
                print(command[0])
                if command[0] == "":
                    print(command[1])
                    if command[1] == "play":
                        userJoined(s,u,playerlist,players)
                    elif command[1] == "tables":
                        #returns the list of tables in format "/tables/numberOfTables/tableId"
                        if u in players:
                            returnTables(tables,u)
                        else:
                            sendMessage(s,u,"/no/register")
                        #adds player to the chosen table,seat with chosen amount of chips
                    elif command[1] == "join":
                        if u in players:
                            playerlist[u].joinTable(tables[int(command[2])],int(command[3]))
                            print(tables[int(command[2])].users)
                        else:
                            sendMessage(s,u,"/no/register")
                        #user leave the table
                    elif command[1] == "leave":
                        if u in players:
                            if playerlist[u].table != None:
                                playerlist[u].leaveTable()
                        else:
                            sendMessage(s,u,"/no/register")
                        #user wants to skip his step
                    elif command[1] == "players":
                        if u in players:
                            if playerlist[u].table != None:
                                playerlist[u].sendPlayers()
                        else:
                            sendMessage(s,u,"/no/register")
                        #user wants to skip his step
                    elif command[1] == "check":
                        if u in players:
                            if playerlist[u].table != None:
                                if playerlist[u].table.inGame == True:
                                    if playerlist[u] in playerlist[u].table.game.players:
                                        if u == playerlist[u].table.game.currentMover:
                                            #should check whether his step
                                            playerlist[u].table.game.check(u)
                                        else:
                                            sendMessage(s,u,"/no/wait")
                                    else:
                                        sendMessage(s,u,"/no/notplaying")
                                else:
                                    sendMessage(s,u,"/no/gamewait")
                            else:
                                sendMessage(s,u,"/no/join")
                        else:
                            sendMessage(s,u,"/no/register")
                        #user wants to increase the bet amount
                    elif command[1] == "bet":
                        if u in players:
                            if playerlist[u].table != None:
                                if playerlist[u].table.inGame == True:
                                    if playerlist[u] in playerlist[u].table.game.players:
                                        if u == playerlist[u].table.game.currentMover:
                                            #should check whether his step
                                            playerlist[u].table.game.bet(u,int(command[2]))
                                        else:
                                            sendMessage(s,u,"/no/wait")
                                    else:
                                        sendMessage(s,u,"/no/notplaying")
                                else:
                                    sendMessage(s,u,"/no/gamewait")
                            else:
                                sendMessage(s,u,"/no/join")
                        else:
                            sendMessage(s,u,"/no/register")
                        #user wants to fall his cards
                    elif command[1] == "fold":
                        if u in players:
                            #check if user is among players
                            if playerlist[u].table != None:
                                #check if user player joined any tables
                                if playerlist[u].table.inGame == True:
                                    #check whether table is playing now
                                    if playerlist[u] in playerlist[u].table.game.players:
                                        #should check whether user is among players
                                        if u == playerlist[u].table.game.currentMover:
                                            #should check whether his step
                                            playerlist[u].table.game.fold(u)
                                        else:
                                            sendMessage(s,u,"/no/wait")
                                    else:
                                        sendMessage(s,u,"/no/notplaying")
                                else:
                                    sendMessage(s,u,"/no/gamewait")
                            else:
                                sendMessage(s,u,"/no/join")
                        else:
                            sendMessage(s,u,"/no/register")
                    #otherwise return undefined error
                    else:
                        sendMessage(s,u,"/no/undefined")




socket = StartConnection("86.36.46.10", 15112)
while not login (socket, "dealer", "dealer"):
    print ("Something went wrong, launch the program again")
players = []
playerlist = {}
tables = []
wnd = tkinter.Tk()
wnd.title("Dealer")
dealerApp = startWnd(wnd)
wnd.mainloop()
