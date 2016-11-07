# README #
## update on Nov 5 ##
Force pushed and forgot to edit the readme.

Newly updated one, successfully passed all the tests. Main file is "lab2stack.py", folder "keys", files "CertFactory.py", "MyTimer.py" are necessary, others are just used for test.

File "MyTimer.py" is modified from "playground.network.comoon.Timer", which is created by Seth, the class teacher


-------------------------------------------------------

## update on Nov 1st ##
This protocol implemented handshake and one-direction data flow from client to server, due to my misunderstanding of the protocol, I didn't implement the other direction of data flow. That's to say, client writes, and server sends ACK, if server wants to send back data, it should be included in the ACK packet, this is what my protocol does.

So, score 50% at most, because I realized it just now and no enough time to modify the code.

Attention: I've write one line hard code about importing the root cert, may need to be modified for tests.

I tested in my computer and the result is that the server passes [1100, 1200, 1201], the client passes [1200, 1201], and then the SeqNum of the packet received mixed with the AckNum.