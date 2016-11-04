# go on statemachine and handshake
# handshake phase:
# client: cert[cNonce, mycert, CAcert], SEQ, SEQF
# server: check(checkCerts, IP), send(SIGN=prikey(cNonce+1), cert[sNonce, myCert, CAcert]
#         , SEQ, SEQF, ACK=cSEQ+1, ACKF]
# client: check(checkCerts, IP, SIGN = cNonce+1), send(SIGN=prikey(sNonce+1), SEQ=cSEQ+1, SEQF, ACK=sSEQ+1, ACKF]
# During transmission, every transmit sends a packet contains 5(DEFAUT_WINDOW_SIZE) small data packets, the server
# will authenticate and give ack, then the client sends the next packet contains 5 data packets. If any info lost in
# the packet, server won't response a ack.
# If the client uses loseConnection() before data transmitted, server will immediately change to CLOSE_RECV state, and
# send the ack of Close, otherwise when loseConnection() is called, all data must be transmitted since after received
# ack it will start loseConnection()
# SEQ = lastpacket(LP)'s SEQ + LP's data length
# ACK = RP's SEQ + RP's data length


# PROBLEMS:
# no recovery
# PATHONPATH=~/network/playground-fall-2016/src/ python test_throughput.py res.txt ~/network/playground-fall-2016/src/ --stack=apps.samples.lab2stack

import os
import threading
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5

from myProtocol import CertFactory
from playground.crypto import X509Certificate
from playground.network.common.Protocol import StackingTransport, \
    StackingProtocolMixin, StackingFactoryMixin, MessageStorage
from playground.network.common.statemachine import StateMachine
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING, UINT4, BOOL1, DEFAULT_VALUE, LIST, OPTIONAL, \
    UINT1
from twisted.internet import error
from twisted.internet.protocol import Protocol, ClientFactory, ServerFactory
from twisted.python import failure

DEFAULT_WINDOW_SIZE = 1
DEFAULT_SEGMENT_SIZE = 4096

# !IMPORTANT
# HARD CODE HERE
rootCertData = CertFactory.getRootCert()
rootCert = X509Certificate.loadPEM(rootCertData)
priKey = RSA.importKey(CertFactory.getPrivateKeyForAddr())

clientNonce = os.urandom(8).encode('hex')  # random.randint(0, 65535)
serverNonce = os.urandom(8).encode('hex')
DEFAULT_CLIENT_SESSION = str(clientNonce) + str(serverNonce)

connectionDone = failure.Failure(error.ConnectionDone())
connectionDone.cleanFailure()


class MyMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "myProtocol.MyProtocolStack.MyMessage"
    MESSAGE_VERSION = "1.0"

    BODY = [
        ("SeqNum", UINT4),
        ("AckNum", UINT4, OPTIONAL),
        ("Signature", STRING, DEFAULT_VALUE("")),
        ("Cert", LIST(STRING), OPTIONAL),
        ("AckFlag", BOOL1, DEFAULT_VALUE(False)),
        ("SessionID", STRING, OPTIONAL),
        ("CloseFlag", BOOL1, DEFAULT_VALUE(False)),
        ("SeqNumNotiFlag", BOOL1, DEFAULT_VALUE(False)),
        ("ResetFlag", BOOL1, DEFAULT_VALUE(False)),
        ("Data", STRING, DEFAULT_VALUE("")),
        ("OPTIONS", LIST(STRING), OPTIONAL)
    ]


class state(object):
    SNN_SENT = "first SNN sent"
    ESTABLISHED = "Established"
    CLOSEREQ = "Close request"
    CLOSERECV = "Close request received"
    CLOSED = "Closed"
    # server
    LISTENING = "Listening"
    SNN_RECV = "SNN received and have sent ack"


class signal(object):
    SYN_SEND = "SNN sent"
    ACK_RECEIVED = "Acknowledgement received"
    CLOSE = "Close"
    CLOSE_REQ = "Close request"
    CLOSE_ACK = "Close acknowledgement"
    RESET = "reset"
    # server
    SYN_RECEIVED = "Handshake syn flag received"


class errType(object):
    GENERAL = "General"
    HANDSHAKE = "Handshake"
    TRANSMISSION = "transmission"


# ----------------------------------
# server
class RIPTransport(StackingTransport):
    __resendsSeq = []  # store currently sent packets' SeqNum
    __resendsValue = []  # store currently sent packets' data
    __lastAckNum = 0  # store the next AckNum, so if the received AckNum smaller than it, some packets should be resent

    def __init__(self, lowerTransport, initSeqNum, protocol):
        self.__initPacketSN = initSeqNum
        self.__seqNum = initSeqNum
        self.__protocol = protocol
        self.__timer = threading.Timer(120, self.reSendDataPacket, 0)
        StackingTransport.__init__(self, lowerTransport)

    def write(self, data):
        count = 1
        raw = []
        self.__dataValues = []
        self.__dataSeqs = []
        while data:
            raw.append([self.__seqNum + count * (DEFAULT_SEGMENT_SIZE + 1), data[:DEFAULT_SEGMENT_SIZE]])
            data = data[DEFAULT_SEGMENT_SIZE:]
            count += 1
        raw.sort()
        for ele in raw:
            self.__dataSeqs.append(ele[0])
            self.__dataValues.append(ele[1])
        self.sendMsg(0)

    def loseConnection(self):
        self.lowerTransport().write(self.buildClosePacket().__serialize__())
        self.__protocol.setSMCloseReq()
        self.startTimer(1)

    def sendMsg(self, ackNum):
        self.__resendsSeq = []
        self.__resendsValue = []
        # pushFlag = False
        start = 0
        if ackNum:
            if ackNum < self.__lastAckNum:
                self.reSendDataPacket(ackNum)
                # print "line438"
                self.startTimer()
                return
            else:
                try:
                    start = self.__dataSeqs.index(ackNum)
                except Exception, e:
                    print e
        for i in range(start, start + DEFAULT_WINDOW_SIZE):
            if i < len(self.__dataSeqs):
                # if i == len(self.__dataSeqs) - 1:
                # pushFlag = True
                packet = self.buildDataPacket(self.__dataSeqs[i], self.__dataValues[i])
                self.__resendsSeq.append(self.__dataSeqs[i])
                self.__resendsValue.append(self.__dataValues[i])
                self.lowerTransport().write(packet.__serialize__())
        self.__protocol.sm.currentState() != state.CLOSED and self.startTimer()
        self.__lastAckNum = start + DEFAULT_WINDOW_SIZE < len(self.__dataSeqs) and self.__dataSeqs[start + DEFAULT_WINDOW_SIZE]

    def startTimer(self, state=0):
        # print "start timer"
        if state:
            self.__timer = threading.Timer(120, self.reSendClosePacket)
        else:
            self.__timer = threading.Timer(120, self.reSendDataPacket, 0)
        self.__timer.start()

    def stopTimer(self):
        # print "stop timer"
        self.__timer and self.__timer.cancel()

    def buildDataPacket(self, seq, data, push=False):
        packet = MyMessage()
        packet.SeqNum = seq
        packet.Data = data
        # packet.PushFlag = push
        packet.Signature = buildSign(packet.__serialize__())
        return packet

    def reSendDataPacket(self, ackNum):
        if not ackNum:
            t = 0
        else:
            t = self.__resendsSeq.index(ackNum)
        for i in range(t, DEFAULT_WINDOW_SIZE):
            self.lowerTransport().write(
                self.buildDataPacket(self.__resendsSeq[i], self.__resendsValue[i]).__serialize__())
            # self.startTimer()
            # print "resenddata"

    def reSendClosePacket(self):
        self.lowerTransport().write(self.buildClosePacket(self.__initPacketSN).__serialize__())
        # self.startTimer(1)
        # print "resendclose"

    def buildClosePacket(self):
        packet = MyMessage()
        packet.SeqNum = self.__seqNum
        packet.CloseFlag = True
        packet.Signature = buildSign(packet.__serialize__())
        return packet



class MyServerProtocol(StackingProtocolMixin, Protocol):
    __initialSN = random.randint(0, pow(2, 32))

    def __init__(self, isClient=False):
        # self.__protocolStack = protocolStack
        self.__isClient = isClient
        self.sm = StateMachine("StateMachine")
        self.__storage = MessageStorage()
        self.setupServerSM()

        certs = CertFactory.getCertsForAddr()
        self.myCertData = certs[0]
        self.CACertData = certs[1]

        self.__buffer = ""  # for data received
        # self.__bufCount = 0  # for count packet until it reachs WindowSize
        self.__dataBuf = ""  # store the data received
        self.__lastPacket = ""  # the last sent packet used when reset flag is true
        self.__timer = threading.Timer(120, self.reSendLastPacket)
        self.__dataPacketSeq = []  # store all the packet SeqNum received, used for check
        self.__ackNum = 0  #
        # self.__nextSeqNum = self.__initialSN  # next packet's sequence number
        # self.__buffer = ""
        # self.__dataBuf = ""

        # self.__timer = threading.Timer(120, self.resendHS, self.sm.currentState())

    def setupServerSM(self):
        self.sm.addState(state.LISTENING, (signal.SYN_RECEIVED, state.SNN_RECV), (signal.SYN_SEND, state.SNN_SENT),
                         onEnter=self.onClose)
        self.sm.addState(state.SNN_SENT, (signal.ACK_RECEIVED, state.ESTABLISHED), (signal.RESET, state.LISTENING))
        self.sm.addState(state.SNN_RECV, (signal.ACK_RECEIVED, state.ESTABLISHED), (signal.RESET, state.LISTENING))
        self.sm.addState(state.ESTABLISHED, (signal.CLOSE_REQ, state.CLOSERECV),
                         (signal.CLOSE, state.CLOSEREQ), (signal.RESET, state.SNN_RECV), onEnter=self.onEstablished)

        self.sm.addState(state.CLOSEREQ, (signal.CLOSE_ACK, state.LISTENING), (signal.RESET, state.LISTENING))
        self.sm.addState(state.CLOSERECV, (signal.CLOSE, state.LISTENING))
        # ESTABLISHED receive close packet and change to CLOSERECV, after send the ACK, change to LISTENING
        # so from ESTABLISHED to LISTENGING only receive one packet, in CLOSERECV state won't receive packet
        # self.sm.addState(state.CLOSED, onEnter=self.onClose)
        self.sm.start(state.LISTENING)

        # self.sm.addState(state.ESTABLISHED, (signal.CLOSE, state.CLOSEREQ), (signal.RESET, state.SNN_SENT), onEnter=self.onEstablished)

    def onClose(self, signal, data):
        if self.__isClient:
            print '[CLOSED]'
            del self.__timer
            self.transport.loseConnection()

    def onEstablished(self, signal, data):
        print '[ESTABLISHED]'
        self.higherTransport = RIPTransport(self.transport, self.__nextSeqNum, self)
        self.makeHigherConnection(self.higherTransport)

    def connectionMade(self):
        self.sendFHSPacket()
        # self.__protocolStack[self.transport.getPeer()[0]] = self
        # self.higherTransport = MyServerTransport(self.transport)
        # self.makeHigherConnection(self.higherTransport)

    def sendFHSPacket(self):
        # print 'first sent'
        msgToSend = self.buildFHSPacket()
        self.transport.write(msgToSend.__serialize__())
        self.__lastPacket = msgToSend
        self.sm.signal(signal.SYN_SEND, "")
        self.startTimer()

    def buildFHSPacket(self):
        initialMsg = MyMessage()
        initialMsg.SeqNum = self.__initialSN
        initialMsg.SeqNumNotiFlag = True
        initialMsg.SessionID = DEFAULT_CLIENT_SESSION
        initialMsg.Cert = [str(clientNonce), self.myCertData, self.CACertData]
        initialMsg.Signature = buildSign(initialMsg.__serialize__())
        return initialMsg

    def connectionLost(self, reason=connectionDone):
        if reason.getErrorMessage() == connectionDone.getErrorMessage():
            self.higherProtocol().connectionLost(reason)

    def startTimer(self):
        self.__timer = threading.Timer(120, self.reSendLastPacket)
        # self.__timer = threading.Timer(120, self.resendHS)
        # self.__timer.start()
        self.__timer.start()

    def stopTimer(self):
        self.__timer and self.__timer.cancel()

    def resendHS(self):
        if self.sm.currentState() == state.SNN_SENT:
            print "[RESEND HANDSHAKE]"
            self.sendFHSPacket()

    def reSendLastPacket(self):
        self.transport.write(self.__lastPacket)

    def dataReceived(self, data):
        self.stopTimer()
        # print "[dataReceived]"  # my IP
        self.__buffer += data
        while self.__buffer:
            msg, byte = MyMessage.Deserialize(self.__buffer)
            self.__storage.update(self.__buffer[:byte])
            self.__buffer = self.__buffer[byte:]
        for msg in self.__storage.iterateMessages():
            # after handshake phase 1, got clientPubKey, then authenticate
            if self.sm.currentState() != state.LISTENING or self.sm.currentState() != state.SNN_SENT:
                if not self.checkSign(msg):  # hasattr(self, 'clientPubKey'):
                    # failed during data exchange, pass
                    # failed during handshake, reset
                    # if self.sm.currentState() == state.SNN_RECV:
                    if self.sm.currentState() != state.ESTABLISHED:
                        self.authenticationFail()
                elif msg.ResetFlag:
                    # all reset packets include SNN
                    # print "[SERVER RESET]"
                    if not msg.SeqNum == self.__peerISN - 1:
                        continue
                    self.initialize()
                    if self.__isClient:  # client
                        self.sendFHSPacket()
                    else:
                        if not self.processHSFirst(msg):  # server
                            self.authenticationFail()
                            return
                        self.sm.signal(signal.SYN_RECEIVED, msg)
                return
            if msg.SeqNum != self.__ackNum:
                continue
            if self.sm.currentState() == state.LISTENING:  # handshake phase 1
                if not self.processHSFirst(msg):
                    self.authenticationFail()
                    return
                self.sm.signal(signal.SYN_RECEIVED, msg)
            elif self.sm.currentState() == state.SNN_SENT:  # handshake phase 2
                if not self.processHSSecond(msg):
                    self.authenticationFail()
                    return
                self.sm.signal(signal.ACK_RECEIVED, msg)
            elif self.sm.currentState() == state.SNN_RECV:  # handshake phase 3
                if not self.processHSThird(msg):
                    self.authenticationFail()
                    return
                self.sm.signal(signal.ACK_RECEIVED, msg)
            elif self.sm.currentState() == state.CLOSEREQ:
                # self.higherTransport.stopTimer()
                self.sm.signal(signal.CLOSE_ACK, "")
            elif self.sm.currentState() == state.ESTABLISHED:
                # self.higherTransport.stopTimer()
                if msg.CloseFlag:
                    print '[CLOSED]'
                    if msg.SeqNum == self.__peerISN:
                        self.sm.signal(signal.CLOSE_REQ, msg)
                        self.higherTransport.write(self.buildAckPacket(msg))
                        self.sm.signal(signal.CLOSE, msg)
                elif self.__isClient:
                    # print "[CHECK] data received"
                    self.higherTransport.sendMsg(msg.AckNum)
                else:
                    self.processData(msg)

    def processHSFirst(self, msg):  # server
        if not self.checkHSPacket(msg):
            return False
        self.__peerISN = msg.SeqNum + 1
        msgToSend = self.sendSHSPacket(msg)
        self.transport.write(msgToSend.__serialize__())
        self.__lastPacket = msgToSend
        # print '[CHECK] phase 1 end'
        return True

    def sendSHSPacket(self, msg):  # server
        msgToSend = MyMessage()
        msgToSend.SeqNum = self.__initialSN
        msgToSend.SessionID = msg.SessionID[len(msg.Cert[0]):] + msg.SessionID[:len(msg.Cert[0])]
        self.__ackNum = msg.SeqNum + 1
        msgToSend.AckNum = self.__ackNum
        msgToSend.AckFlag = True
        msgToSend.Cert = [self.serverNonce, intToNonce(int(msg.Cert[0], 16) + 1), self.myCertData, self.CACertData]
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def processHSSecond(self, msg):  # client
        if not self.checkHSPacket(msg):
            return False
        self.__peerISN = msg.SeqNum + 1
        msgToSend = self.sendTHSPacket(msg)
        self.transport.write(msgToSend.__serialize__())  # try to transport my msg
        self.__lastPacket = msgToSend
        # print '[CHECK] phase 2 end'
        return True

    def sendTHSPacket(self, msg):
        msgToSend = MyMessage()
        msgToSend.Cert = [intToNonce(int(msg.Cert[0], 16) + 1)]
        msgToSend.SeqNum = self.__initialSN + 1
        # msgToSend.SeqNumNotiFlag = True
        msgToSend.SessionID = DEFAULT_CLIENT_SESSION
        self.__ackNum = msg.SeqNum + 1
        msgToSend.AckNum = self.__ackNum
        msgToSend.AckFlag = True
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def processHSThird(self, msg):
        if not self.checkTHSPacket(msg):
            return False
        # no need to add ACK or nextSEQ
        # self.__ackNum = msg.SeqNum + (len(msg.Data) or 1)
        print '[ESTABLISHED]'
        return True

    def processData(self, msg):
        # self.__dataPacketSeq.append(msg.SeqNum)
        # if self.__bufCount < self.windowSize:
        #     # not all data packets received
        #     self.__dataBuf += msg.Data
        #     self.__bufCount += 1
        #     self.__ackNum = msg.SeqNum + len(msg.Data) + 1
        # if self.__bufCount == self.windowSize or msg.PushFlag:
        # have received all packets, send ack
        # self.__bufCount = 0
        packetToSent = self.buildAckPacket(msg)
        # if msg.PushFlag:
        self.higherProtocol() and self.higherProtocol().dataReceived(self.__dataBuf)
        self.initialize()
        # packetToSent.PushFlag = True
        self.higherTransport.write(packetToSent)

    def checkHSPacket(self, msg):
        cert1 = X509Certificate.loadPEM(msg.Cert[2 if self.__isClient else 1])
        cert2 = X509Certificate.loadPEM(msg.Cert[3 if self.__isClient else 2])
        peerPubKeyBlock = cert2.getPublicKeyBlob()
        # if self.__isClient:
        #     self.serverPubKey = RSA.importKey(pubKeyBlock)
        # else:
        #     self.clientPubKey = RSA.importKey(pubKeyBlock)
        self.peerPubKey = RSA.importKey(peerPubKeyBlock)
        # check Ack
        # 0. Check signature
        if not self.checkSign(msg):
            return False
        # 1.server do check IP
        if cert1.getSubject()["commonName"] != self.transport.getPeer()[0]:
            self.log(errType.HANDSHAKE, "IP false")
            return False
        # 2, 3, 4: checkCerts
        res = checkCerts(self, cert1, cert2)
        if not res:
            self.log(errType.HANDSHAKE, "checkCerts false")
            return False
        if self.__isClient:
            # 5.public key check the signature of nonce1
            checkSignature = intToNonce(int(clientNonce, 16) + 1) == msg.Cert[1]
            if not checkSignature:
                self.log(errType.HANDSHAKE, "wrong nonce1")
                return False
        else:
            # get server's nonce
            if msg.SessionID[:len(msg.Cert[0])] != msg.Cert[0]:
                self.log(errType.HANDSHAKE, "wrong client nonce")
                return False
            self.serverNonce = msg.SessionID[len(msg.Cert[0]):]
        return True


    def checkTHSPacket(self, msg):
        if not intToNonce(int(self.serverNonce, 16) + 1) == msg.Cert[0]:
            self.log(errType.HANDSHAKE, "wrong signature")
            return False
        return True

    # def checkDataPacket(self, msg):
    #     if msg.WindowSize != self.windowSize:
    #         self.log(errType.TRANSMISSION, "window size error")
    #         return False
    #     if msg.MaxSegSize != self.segSize:
    #         self.log(errType.TRANSMISSION, "segment size error")
    #         return False
    #     return True

    def buildAckPacket(self, msg, resetAck=False):
        msgToSend = MyMessage()
        self.__serverInitialSN += 1
        msgToSend.SeqNum = self.__serverInitialSN
        if resetAck:
            msgToSend.AckNum = self.__ackNum
        else:
            msgToSend.AckNum = msg.SeqNum + len(msg.Data) + 1
        msgToSend.AckFlag = True
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def buildResetPacket(self):
        msgToSend = MyMessage()
        msgToSend.SeqNum = self.__initialSN
        msgToSend.SeqNumNotiFlag = True
        msgToSend.ResetFlag = True
        if self.__isClient:
            msgToSend.SessionID = DEFAULT_CLIENT_SESSION
            msgToSend.Cert = [str(clientNonce), self.myCertData, self.CACertData]
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def authenticationFail(self):
        self.initialize()
        self.transport.write(self.buildResetPacket().__serialize__())
        if self.__isClient:
            self.sm.signal(signal.SYN_SEND, "")

    def initialize(self):
        self.sm.signal(signal.RESET, "")
        self.__ackNum = 0
        self.__dataBuf = ""
        self.__lastPacket = ""
        self.__buffer = ""

    def checkSign(self, msg):
        checkSignature = checkPacketSign(self.clientPubKey, msg)
        if not checkSignature:
            self.log(errType.HANDSHAKE, "signature false")
        return checkSignature

    def log(self, type, msg):
        print '[' + type + ']: ' + msg


class MyServerFactory(StackingFactoryMixin, ServerFactory):
    # protocolStack = {}
    # FixedKey = "PASSWORD"
    def buildProtocol(self, addr):
        # print "server build"
        # print self.protocolStack
        return MyServerProtocol()


# ------------------------------------------------------------------
# below are client


class MyClientProtocol(StackingProtocolMixin, Protocol):
    __clientInitialSN = random.randint(0, pow(2, 32))

    def __init__(self, factory):
        self.__factory = factory
        self.__storage = MessageStorage()
        self.__buffer = ""
        self.__dataBuf = ""

        self.sm = StateMachine("ClientStateMachine")
        self.setupClientSM()
        # self.__timer = threading.Timer(120, self.resendHS, self.sm.currentState())

        certs = CertFactory.getCertsForAddr()
        self.myCertData = certs[0]
        self.CACertData = certs[1]

    def setupClientSM(self):
        self.sm.addState(state.SNN_SENT, (signal.ACK_RECEIVED, state.ESTABLISHED), (signal.RESET, state.SNN_SENT))
        self.sm.addState(state.ESTABLISHED, (signal.CLOSE, state.CLOSEREQ), (signal.RESET, state.SNN_SENT),
                         onEnter=self.onEstablished)
        self.sm.addState(state.CLOSEREQ, (signal.CLOSE_ACK, state.CLOSED), (signal.RESET, state.SNN_SENT))
        self.sm.addState(state.CLOSED, (signal.SYN_SEND, state.SNN_SENT), onEnter=self.onClose)
        self.sm.start(state.CLOSED)

    def onEstablished(self, signal, data):
        print '[ESTABLISHED]'
        # self.higherTransport = MyServerTransport(self.transport, self.__clientInitialSN + 1, self)
        self.makeHigherConnection(self.higherTransport)

    def onClose(self, signal, data):
        print '[CLOSED]'
        del self.__timer
        self.transport.loseConnection()
        # self.higherTransport.loseConnection()

    def startTimer(self):
        self.__timer = threading.Timer(120, self.resendHS)
        self.__timer.start()

    def stopTimer(self):
        self.__timer.cancel()

    def resendHS(self):
        if self.sm.currentState() == state.SNN_SENT:
            print "[RESEND HANDSHAKE]"
            self.sendFHSPacket()

    def connectionMade(self):
        self.sendFHSPacket()
        self.sm.signal(signal.SYN_SEND, "")

    def connectionLost(self, reason=connectionDone):
        if reason.getErrorMessage() == connectionDone.getErrorMessage():
            self.higherProtocol().connectionLost(reason)

    def sendFHSPacket(self):
        # print 'first sent'
        self.transport.write(self.buildFHSPacket().__serialize__())
        self.startTimer()

    def buildFHSPacket(self):
        initialMsg = MyMessage()
        initialMsg.SeqNum = self.__clientInitialSN
        initialMsg.SeqNumNotiFlag = True
        initialMsg.SessionID = DEFAULT_CLIENT_SESSION
        initialMsg.Cert = [str(clientNonce), self.myCertData, self.CACertData]
        initialMsg.Signature = buildSign(initialMsg.__serialize__())
        return initialMsg

    def dataReceived(self, data):
        self.__buffer += data
        while self.__buffer:
            msg, byte = MyMessage.Deserialize(self.__buffer)
            self.__storage.update(self.__buffer[:byte])
            self.__buffer = self.__buffer[byte:]
        for msg in self.__storage.iterateMessages():
            if self.sm.currentState() != state.SNN_SENT:  # hasattr(self, 'clientPubKey'):
                if not self.checkSign(msg):
                    self.authenticationFail()
                    return
            if msg.ResetFlag:
                print "[CLIENT RESET]"
                self.initialize()
            elif self.sm.currentState() == state.SNN_SENT:
                self.stopTimer()
                if not self.processHSSecond(msg):
                    return
                self.sm.signal(signal.ACK_RECEIVED, msg)
            elif self.sm.currentState() == state.CLOSEREQ:
                self.higherTransport.stopTimer()
                self.sm.signal(signal.CLOSE_ACK, "")
            else:
                self.higherTransport.stopTimer()
                # if type(msg.Cert) == "list":
                #     if not self.processHSSecond(msg):
                #         return
                if msg.Data:
                    self.__dataBuf += msg.Data
                if msg.PushFlag:
                    self.higherProtocol() and self.higherProtocol().dataReceived(self.__dataBuf)
                    self.initialize()
                else:
                    self.higherTransport.sendMsg(msg.AckNum)

    def processHSSecond(self, msg):
        if not self.checkSHSPacket(msg):
            self.transport.write(self.buildResetPacket().__serialize__())
            return False
        msgToSend = self.sendTHSPacket(msg)
        self.transport.write(msgToSend.__serialize__())  # try to transport my msg
        print '[CHECK] client shakehand end'
        return True

    def initialize(self):
        self.__dataBuf = ""

    def buildResetPacket(self):
        msgToSend = self.buildFHSPacket()
        msgToSend.ResetFlag = True
        msgToSend.Signature = ""
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    # def checkSHSPacket(self, msg):

    def sendTHSPacket(self, msg):
        msgToSend = MyMessage()
        msgToSend.Cert = [intToNonce(int(msg.Cert[0], 16) + 1)]
        msgToSend.SeqNum = self.__clientInitialSN
        # msgToSend.SeqNumNotiFlag = True
        msgToSend.SessionID = DEFAULT_CLIENT_SESSION
        msgToSend.AckNum = msg.SeqNum + 1
        msgToSend.AckFlag = True
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def authenticationFail(self):
        self.higherTransport.write(self.buildResetPacket())

    def checkSign(self, msg):
        checkSignature = checkPacketSign(self.serverPubKey, msg)
        if not checkSignature:
            self.log(errType.HANDSHAKE, "signature false")
        return checkSignature

    def setSMCloseReq(self):
        self.sm.signal(signal.CLOSE, "")

    def log(self, type, msg):
        print '[' + type + ']: ' + msg


class MyClientFactory(StackingFactoryMixin, ClientFactory):
    def buildProtocol(self, addr):
        # print "client build"
        return MyClientProtocol(self, True)

        # def clientConnectionLost(self, connector, reason):
        #     # print('line670, Lost connection.  Reason:', reason)
        #     connector.connect()
        #     # reactor.stop()


# ------------------------------------------
# public functions

def checkCerts(obj, cert1, cert2):
    # 2.check cert1's sign is the cert2's subject
    if cert1.getIssuer() != cert2.getSubject():
        obj.log(errType.HANDSHAKE, 'cert sign wrong:')
        return False
    # 3.use public key in cert2 to check cert1
    peerPubKeyBlock = cert2.getPublicKeyBlob()
    peerPubKey = RSA.importKey(peerPubKeyBlock)
    CAVerifier = PKCS1_v1_5.new(peerPubKey)
    hasher = SHA256.new()
    data = cert1.getPemEncodedCertWithoutSignatureBlob()
    hasher.update(data)
    CAResult = CAVerifier.verify(hasher, cert1.getSignatureBlob())
    if not CAResult:
        obj.log(errType.HANDSHAKE, 'CA wrong')
        return False

    # 4.check cert2's sign is the root
    if cert2.getIssuer() != rootCert.getSubject():
        obj.log(errType.HANDSHAKE, 'root sign wrong:')
        return False
    rootPublicKeyBlock = rootCert.getPublicKeyBlob()
    rootPublicKey = RSA.importKey(rootPublicKeyBlock)
    rootVerifier = PKCS1_v1_5.new(rootPublicKey)
    rootHasher = SHA256.new()
    CAdata = cert2.getPemEncodedCertWithoutSignatureBlob()
    rootHasher.update(CAdata)
    rootResult = rootVerifier.verify(rootHasher, cert2.getSignatureBlob())
    if not rootResult:
        obj.log(errType.HANDSHAKE, 'root wrong')
        return False
    return True


def buildSign(data):
    return PKCS1_v1_5.new(priKey).sign(SHA256.new(data))


def checkSign(key, data, signature):
    return PKCS1_v1_5.new(key).verify(SHA256.new(data), signature)


def checkPacketSign(key, packet):
    sign = packet.Signature
    packet.Signature = ""
    return checkSign(key, packet.__serialize__(), sign)


def intToNonce(i):
    h = hex(i)
    h = h[2:]
    if h[-1] == 'L':
        h = h[:-1]
    return h


ConnectFactory = MyClientFactory
ListenFactory = MyServerFactory
