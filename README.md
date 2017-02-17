# Encrypted-Messenger-P2P-

# Created by Chris Benka on 2/17/17.
# Copyright 2017 Chris Benka. All rights reserved.
#This application is a simple encrypted peer to peer architecture (P2P)
#chat application.
#The application simply parses arguments given by the user in the temrinal
#so that the first user may act as the server abd the second user may act
#as the client. The applciation uses the select module to identify the first
#useable readbale input(standard input or socket), and either receives data
#via the socket object and prints the message to standard output or sends
#a message to the other user via the socket object.

#The program uses AES 256 bit encryption based off of the configuration key
# and the authentication key given in the command line. The 256 bit hashed versions of each
#each of these given keys are used to generate Message Authenication codes for
#checking integiry of the message and for the encryption of the message.
#The following encryption scheme is Mac-Then Encrypt, in which a MAC is produced
#based on the plaintext and then the plaintext and the MAC
#are encrytped together to produce a ciphertext based off of both. The ciphertext
#is then sent. IF the message authencation codes are not the same between the two
#machines an error message will appear on the recieving machine's terminal window
#indicating that there was an error verifying the integiry of the message.


#instruction to compile and execute program.Please note server and client
#users must be run on two different terminals.

    #Python encryptedIM.py --s --configkey foobar --authkey --Hello
    #Python encryptedIM.py --c localhost --configkey foobar --authkey --Hello
#To exit program simply press #cntrl-C
