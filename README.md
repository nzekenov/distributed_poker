# pokerOnline

Welcome.

Here will be my 15-112 project - Poker Online.

Poker Online is network based version of the popular card game - Poker. Here, in GitHub repository, you will find two codes: Client (For Players) and Server (For Dealer). 

If you already have a network, and Dealer on the network, you can download Client code (client.py) and start playing Poker with your friends. If not, then you can set up own network and run Dealer's (dealer.py) code and configure it on your network so that anyone connect and play.

Functionality:
Dealer (Game Engine): 
- Start Games if two or more people joined table (Will be several different tables with capacity of up to 9 people)
- Mix card stack
- Share cards to each player
- Open cards
- Make an order of players
- Determine the winner
- Give time for each client to move (if client takes more time than given, automatically consider as Fold)

Client:
- Can join to the game (Up to 9 people on one table)
- Will initially have 50000 poker chips
- Choose to Bet,Raise,Fold or Check (Poker movements)
- Win/Loss
- Chat with other people sitting the same table

Further improvements:
- Adding types of game (Holdem/Omaha)
- Automatical joining to the Game

