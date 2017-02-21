
# Created by Chris Benka on 2/21/17.
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



import socket
import argparse
import select
import sys
from Crypto.Cipher import AES
from Crypto import Random
import hmac
import hashlib


argsList = sys.argv
#block size in AES CBC mode encryption is 16 bytes
BS = 16



# If the user is the server
if argsList[1] == '--s':
    #create socket object
    s = socket.socket()
    #to allow for easy reuse of port number
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #bind the server socket to any idenitfiable address, and respective port number
    s.bind(('',9999))
    #listen for up to 10 connections
    s.listen(10)
    #accept the connection
    c,addr = s.accept()
    while True:
        list_read = [c] + [sys.stdin]
        #find the first readable input object
        (readd_list,_,_) = select.select(list_read,[],[])
        for item in readd_list:
            #if the first readable input is of type connection
            if item is c:
                #recieve the message
                message = c.recv(1024)
                #Generate 256 bit key for HMAC
                k1 = hmac.new(argsList[5],'',hashlib.sha256)
                #Generate 256 bit key for AES
                k2 = hmac.new(argsList[3],'',hashlib.sha256)

                #partition the recieved message baed on the partion element
                #to obtain iv
                (iv,partitioningItem1,ciphertext) = message.partition('****')
                #Create cipher object based off of 256 bit key  of k2
                cipherObject = AES.new(k2.digest(),AES.MODE_CBC,iv)
                #decrypt the ciphertext of the message
                message = cipherObject.decrypt(ciphertext)
                #unpad the message
                a =0
                try:
                    int(message[0])
                    int(message[1])
                    a = int(message[:2])
                    message = message[2:]
                except ValueError:
                    ad = 3
                try:
                    int(message[0])
                    a = int(message[:1])
                    message = message[1:]
                except ValueError:
                    pas =3
                count =0
                padding = ''
                while(count<a):
                    padding = padding + '$'
                    count = count+1
                message = message.replace(padding,'')

                #message = unpad(message,i,padd)
                #seperate the plaintext from the MAC
                (plaintext,partitioningItem,MAC) = message.partition('!!!!')
                #Using the256 bit key above generate the HMAC off of the plaintext
                hmmmac = hmac.new(k1.digest(),plaintext,hashlib.sha256)

                #if the MACs are different then the auth keys are not the same
                #print an error
                if(str(hmmmac.digest())!=MAC):
                    print "error Sender is using unauthenticated key to send message"

                #otherwise if they are the same then we can safely print
                #the message recieved
                else:
                    print(str(plaintext)),
                    sys.stdout.flush()
            elif item is sys.stdin:
                #Read standard input and send via the connection
                message = sys.stdin.readline()
            #generate 256 bit key to be used for the hmac
                k1 = hmac.new(argsList[5],'',hashlib.sha256)
            #generate the hmac based off the message
                hmmmac = hmac.new(k1.digest(),message,hashlib.sha256)
            #generate 256 bit key based on the configKey
                k2 = hmac.new(argsList[3],'',hashlib.sha256)
                #generate random iv
                iv = Random.new().read(AES.block_size)
                #create cipheroject using k2 and randomly generated iv
                cipherObject = AES.new(k2.digest(),AES.MODE_CBC,iv)
                #concatonate the message and the hmac code
                message =  message + '!!!!' + hmmmac.digest()
                #pad the message
                #message = pad(message,i,padd)

                bytesToMod = (sys.getsizeof(message)-37) % BS
                bytesToMod = BS - bytesToMod
                if(bytesToMod<10):
                    bytesToMod=bytesToMod-1
                elif(bytesToMod>10):
                    bytesToMod = bytesToMod-2
                count = 0
                while count< bytesToMod:
                    message = message + '$'
                    count = count +1
                                #encrypt the message(plaintext,hmac)

                succeeded = False
                message = str(bytesToMod) + message
                while(succeeded==False):
                    try:
                        message = cipherObject.encrypt(message)
                        succeeded = True
                    except ValueError:
                        x = bytesToMod +1
                        message = message.replace(str(bytesToMod),str(x))
                        message = message + '$'

                        bytesToMod = bytesToMod+1

                                #prepend the iv to be used for decyrption
                message =  iv + '****' +  message
                #send the message

                    #send the message
                c.send(message)
        #Terminate the connection
    c.close()
# If the user is the client
elif argsList[1]== '--c':
    s = socket.socket()
    # connect
    #if argsList[2] == 'cjb291-alice':
    if argsList[2] is not None:
        s.connect((argsList[2],9999))
        while True:
            read_list = [s] + [sys.stdin]
            (input_list,_,_) = select.select(read_list,[],[])
            for item in input_list:
                #if first readable input is socket
                if item is s:
                    #recieve message
                    message = s.recv(1024)
                    #Generate 256 bit key for HMAC
                    k1 = hmac.new(argsList[6],'',hashlib.sha256)
                    #Generate 256 bit key for AES
                    k2 = hmac.new(argsList[4],'',hashlib.sha256)
                    #partition the recieved message baed on the partion element
                    #to obtain iv
                    (iv,partitioningItem1,ciphertext) = message.partition('****')
                    #Create cipher object based off of 256 bit key  of k2
                    cipherObject = AES.new(k2.digest(),AES.MODE_CBC,iv)
                    #decrypt the ciphertext of the message
                    message = cipherObject.decrypt(ciphertext)
                    a =0
                    try:
                        int(message[0])
                        int(message[1])
                        a = int(message[:2])
                        message = message[2:]
                    except ValueError:
                        ad = 2

                    try:
                        int(message[0])
                        a = int(message[:1])
                        message = message[1:]
                    except ValueError:
                        ad = 3
                    count =0
                    padding = ''
                    while(count<a):
                        padding = padding + '$'
                        count = count+1
                    message = message.replace(padding,'')



                    #unpad the message
                    #message = unpad1(message,i,padd)
                    #seperate the plaintext from the MAC
                    (plaintext,partitioningItem,MAC) = message.partition('!!!!')
                    #Using the256 bit key above generate the HMAC off of the plaintext
                    hmmmac = hmac.new(k1.digest(),plaintext,hashlib.sha256)

                    #if the MACs are different then the auth keys are not the same
                    #print an error
                    if(str(hmmmac.digest())!=MAC):
                        print "error Sender is using unauthenticated key to send message"
                    #otherwise if they are the same then we can safely print
                    #the message recieved
                    else:
                        print(str(plaintext)),
                        sys.stdout.flush()
                elif item is sys.stdin:
                    #Read standard input
                    message = sys.stdin.readline()
                    #generate 256 bit key to be used for the hmac
                    k1 = hmac.new(argsList[6],'',hashlib.sha256)
                    #generate the hmac based off the message
                    hmmmac = hmac.new(k1.digest(),message,hashlib.sha256)

                    #generate 256 bit key based on the configKey
                    k2 = hmac.new(argsList[4],'',hashlib.sha256)

                    #generate random iv
                    iv = Random.new().read(AES.block_size)
                    #create cipheroject using k2 and randomly generated iv
                    cipherObject = AES.new(k2.digest(),AES.MODE_CBC,iv)

                    #concatonate the message and the hmac code
                    message= message + '!!!!' + hmmmac.digest()
                    #pad the message
                    #message = padding(message,i,padd,BSs)


                    bytesToMod = (sys.getsizeof(message)-37) % BS
                    bytesToMod = BS - bytesToMod
                    if(bytesToMod<10):
                            bytesToMod=bytesToMod-1
                    elif(bytesToMod>10):
                            bytesToMod = bytesToMod-2
                    count = 0
                    while count< bytesToMod:
                        message = message + '$'
                        count = count +1
                    #encrypt the message(plaintext,hmac)

                    succeeded = False
                    message = str(bytesToMod) + message
                    while(succeeded==False):
                        try:
                            message = cipherObject.encrypt(message)
                            succeeded = True
                        except ValueError:
                            x = bytesToMod +1
                            message = message.replace(str(bytesToMod),str(x))
                            message = message + '$'

                            bytesToMod = bytesToMod+1

                    #prepend the iv to be used for decyrption
                    message =  iv + '****' +  message
                    #send the messag
                    s.send(message)
                    #Terminate the connection
        s.close()
    else:
        print("please attempt to correctly connect to alice")
