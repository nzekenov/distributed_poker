# pokerOnline

Welcome.

Here will be my 15-112 project - Poker Online.

Poker Online is network based, digital version of the popular card game - Poker. Poker is multiplayer card game. In this game, Dealer puts random 5 cards from stack on the center of table and give each player 2/4 random cards. At first run, people will decide to bet/check/fold without knowing 5 central cards based only on two cards they already have. Bet - putting poker chips. Check - skip doing anything. Fold - quitting this game. Once someone does a BET, anyone else should decide to raise/call/fold and nobody can check at that point. Call - give the same amount of chips that someone put on BET, Raise - increasing the amount of chips that should be putted. Each increasing of amount will make one more cycle of asking each player to decide on choice. Once cycles of first run ends up, Dealer collects poker chips from each player and put it on the center and then opens first 3 cards on the center. Overall, there will be 3 runs and by the end all 5 cards will be opened. At this point players open/fold their cards and check for the combinations of cards. There are 10 different combinations of cards: High Card, One Pair, Two Pair, Three of a Kind (SET), Straight (5 cards in an order), Flush (5 cards of same suit, Full House (3 & 2 of same cards), Four of a Kind, Straight Flush (5 ordered cards in same suit) and Royal Flush (5 highest ordered cards of the same suit). Each of combinations are ranked where High Card is least and Royal Flush is most ranked combinations. The highest combination of cards will determine the winner(s), and the amount of chips on center will be divided into number of winners.

Here, in my GitHub repository, you will find two code files: Client (For Players) and Dealer (For Dealer). 

If you already have a network, and Dealer on the network, you can download Client code (client.py) and start playing Poker with your friends. If not, then you can set up own network and run Dealer's (dealer.py) code and configure it on your network so that anyone connect and play.

Functionality:

Dealer (Game Engine): 
- Start Games if two or more people joined table (Will be several different tables with capacity of up to 5 people)
- Mix card stack
- Share 2 cards to each player
- Open cards
- Make an order of players
- Determine combinations
- Determine the winner
- Give time for each client to move (if client takes more time than given, automatically consider as Fold)

Client:
- Can join to the game (Up to 5 people on one table)
- Will initially have 50000 poker chips
- Choose to Bet,Raise,Fold or Check (Poker movements)
- Win/Loss

GUI description (You can watch cool video by this link: https://youtu.be/uxiS_aVHGbY):

client.py:
- Once client run client.py, logging in window will appear
- If player sign in successfully, main menu will be shown
- On main menu player can see list of tables with the number of people playing there
- Player can choose a table and join by clicking a button "Join"


Further improvements:
- Adding types of game (Holdem/Omaha)
- Automatical joining to the Game
- Multiplayer mode played on single computer

Preliminary list of python libaries used for this project:
- socket
- tkinter
- Random

Nurassyl Zekenov



