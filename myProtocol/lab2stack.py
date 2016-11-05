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
# PATHONPATH=~/network/playground-fall-2016/src/ python test_throughput.py
# res.txt ~/network/playground-fall-2016/src/ --stack=apps.samples.lab2stack

import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5

from myProtocol import CertFactory
from myProtocol.MyTimer import MyTimer
from playground.crypto import X509Certificate
from playground.network.common.Protocol import StackingTransport, \
    StackingProtocolMixin, StackingFactoryMixin, MessageStorage
from playground.network.common.Timer import callLater
from playground.network.common.statemachine import StateMachine
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING, UINT4, BOOL1, DEFAULT_VALUE, LIST, OPTIONAL
from twisted.internet import error
from twisted.internet.protocol import Protocol, ClientFactory, ServerFactory
from twisted.python import failure

DEFAULT_WINDOW_SIZE = 1
DEFAULT_SEGMENT_SIZE = 4096
TIMEOUT = 0.5

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
    SNN_SENT = "SNN sent"
    ESTABLISHED = "Established"
    CLOSEREQ = "Close request"
    CLOSERECV = "Close request received"
    CLOSED = "Closed"
    # server
    LISTENING = "Listening"
    SNN_RECV = "SNN received"


class signal(object):
    SNN_SEND = "SNN sent"
    ACK_RECEIVED = "Acknowledgement received"
    CLOSE = "Close"
    CLOSING = "Closing"
    CLOSE_REQ = "Close request"
    CLOSE_ACK = "Close acknowledgement"
    RESET = "reset"
    # server
    SNN_RECEIVED = "Handshake SNN received"


class errType(object):
    GENERAL = "GENERAL"
    HANDSHAKE = "HANDSHAKE"
    TRANSMISSION = "TRANSMISSION"
    CHECK = "CHECK"
    TIMER = "TIMER"


# ----------------------------------
# server
class RIPTransport(StackingTransport):
    __dataBuf = ""
    __lastDataPacket = MyMessage()

    def __init__(self, lowerTransport, initSeqNum, protocol):
        self.__seqNum = initSeqNum
        self.__protocol = protocol
        self.__timer = MyTimer(self.resendDataPacket)
        StackingTransport.__init__(self, lowerTransport)

    def startTimer(self):
        # log(errType.TIMER, 'transport start')
        self.__timer.run(TIMEOUT)

    def stopTimer(self, ackNum=0):
        # log(errType.TIMER, 'transport stop')
        self.__timer and self.__timer.cancel()
        if ackNum != self.__seqNum:
            # log(errType.CHECK, '{0} | {1} | {2}'.format(ackNum, self.__seqNum, self.__lastDataPacket.SeqNum))
            if ackNum == self.__lastDataPacket.SeqNum:
                self.resendDataPacket()
                return
        else:
            self.__dataBuf and callLater(0, self.write, "")

    def write(self, data):
        self.__dataBuf += data
        if self.__timer.started():
            # log(errType.CHECK, 'transport timer started')
            return
        if len(self.__dataBuf) >= DEFAULT_SEGMENT_SIZE:
            byteUsed = DEFAULT_SEGMENT_SIZE
        else:
            byteUsed = len(self.__dataBuf)
        # log(errType.CHECK, len(self.__dataBuf), self.__protocol.isClient(), self.__seqNum)
        packet = self.buildDataPacket(self.__dataBuf[:byteUsed])
        self.lowerTransport().write(packet.__serialize__())
        self.__lastDataPacket = packet
        self.__seqNum += byteUsed
        self.__dataBuf = self.__dataBuf[byteUsed:]
        self.startTimer()

    def buildDataPacket(self, data):
        packet = MyMessage()
        packet.SeqNum = self.__seqNum
        packet.Data = data
        packet.Signature = buildSign(packet.__serialize__())
        return packet

    def loseConnection(self):
        # log(errType.CHECK, "lose connection")
        if len(self.__dataBuf) or self.__timer.started():
            callLater(1, self.loseConnection)
        else:
            self.__protocol.closeConnection()

    def realLoseConnection(self):
        super(RIPTransport, self).loseConnection()

    def resendDataPacket(self):
        # log(errType.CHECK, self.__lastDataPacket.SeqNum, self.__protocol.isClient())
        self.lowerTransport().write(self.__lastDataPacket.__serialize__())
        self.startTimer()

    def getDataBuf(self):
        return self.__dataBuf

    def getTimer(self):
        return self.__timer


class RIProtocol(StackingProtocolMixin, Protocol):
    __initialSN = random.randint(0, pow(2, 32))

    def __init__(self, isClient=False):
        self.__isClient = isClient
        self.sm = StateMachine("StateMachine")
        self.__storage = MessageStorage()
        self.setupServerSM()

        certs = CertFactory.getCertsForAddr()
        self.myCertData = certs[0]
        self.CACertData = certs[1]

        self.__buffer = ""  # for data received
        self.__lastPacket = MyMessage()  # the last sent packet used when reset flag is true
        self.__timer = MyTimer(self.reSendLastPacket)
        self.__dataPacketSeq = []  # store all the packet SeqNum received, used for check
        self.__ackNum = 0
        self.__oneBeforeLastAck = 0  # when Ack lost, compare
        self.__peerISN = 0
        self.higherTransport = ""

    def setupServerSM(self):
        self.sm.addState(state.LISTENING, (signal.SNN_RECEIVED, state.SNN_RECV), (signal.SNN_SEND, state.SNN_SENT),
                         (signal.CLOSING, state.LISTENING), onEnter=self.onClose)
        self.sm.addState(state.SNN_SENT, (signal.ACK_RECEIVED, state.ESTABLISHED),
                         (signal.RESET, state.LISTENING))  # client
        self.sm.addState(state.SNN_RECV, (signal.ACK_RECEIVED, state.ESTABLISHED),
                         (signal.RESET, state.LISTENING))  # server
        self.sm.addState(state.ESTABLISHED, (signal.CLOSE_REQ, state.CLOSERECV),
                         (signal.CLOSING, state.CLOSEREQ), (signal.RESET, state.SNN_RECV), onEnter=self.onEstablished)
        self.sm.addState(state.CLOSEREQ, (signal.CLOSE_ACK, state.LISTENING), (signal.RESET, state.LISTENING))
        self.sm.addState(state.CLOSERECV, (signal.CLOSE, state.LISTENING))
        self.sm.start(state.LISTENING)

    def onEstablished(self, sig, data):
        # log(errType.CHECK, '{0} established'.format(self.__isClient))
        self.higherTransport = RIPTransport(self.transport, self.__initialSN + 1, self)
        self.makeHigherConnection(self.higherTransport)

    def connectionMade(self):
        # log(errType.CHECK, self.__isClient + " connection made")
        if self.__isClient:
            self.sendFHSPacket()

    def sendFHSPacket(self):
        msgToSend = self.buildFHSPacket()
        self.transport.write(msgToSend.__serialize__())
        self.__lastPacket = msgToSend
        self.sm.signal(signal.SNN_SEND, "")
        self.startTimer()

    def buildFHSPacket(self):
        initialMsg = MyMessage()
        initialMsg.SeqNum = self.__initialSN
        initialMsg.SeqNumNotiFlag = True
        initialMsg.SessionID = DEFAULT_CLIENT_SESSION
        initialMsg.Cert = [str(clientNonce), self.myCertData, self.CACertData]
        initialMsg.Signature = buildSign(initialMsg.__serialize__())
        return initialMsg

    def onClose(self, sig, data):
        if sig == signal.CLOSING:
            return
        del self.__timer
        self.transport.loseConnection()
        self.higherTransport.realLoseConnection()

    def connectionLost(self, reason=connectionDone):
        Protocol.connectionLost(self, reason=reason)
        self.higherProtocol().connectionLost(reason)
        self.higherProtocol().transport = None
        self.setHigherProtocol(None)

    def startTimer(self):
        # log(errType.TIMER, 'start')
        self.__timer.run(TIMEOUT)

    def stopTimer(self):
        # log(errType.TIMER, 'stop')
        self.__timer and self.__timer.cancel()

    def reSendLastPacket(self):
        # log(errType.CHECK, 'resend')
        self.transport.write(self.__lastPacket.__serialize__())
        self.startTimer()

    def dataReceived(self, data):
        self.stopTimer()
        self.__buffer += data
        while self.__buffer:
            msg, byte = MyMessage.Deserialize(self.__buffer)
            self.__storage.update(self.__buffer[:byte])
            self.__buffer = self.__buffer[byte:]
        for msg in self.__storage.iterateMessages():
            # after handshake phase 1, got clientPubKey, then authenticate
            if (self.sm.currentState() != state.LISTENING and not self.__isClient) or (
                            self.sm.currentState() != state.SNN_SENT and self.__isClient):
                if not self.checkSign(msg):
                    if self.sm.currentState() != state.ESTABLISHED:
                        self.authenticationFail()
                elif msg.ResetFlag:
                    # log(errType.CHECK, 'reset {0}'.format(self.__isClient))
                    if not msg.SeqNum == self.__peerISN - 1:
                        continue
                    self.initialize()
                    if self.__isClient:  # client
                        self.sendFHSPacket()
                    else:
                        if not self.processHSFirst(msg):  # server
                            self.authenticationFail()
                            return
                        self.sm.signal(signal.SNN_RECEIVED, msg)
                    return
            if self.sm.currentState() == state.LISTENING:  # handshake phase 1
                if not self.processHSFirst(msg):
                    self.authenticationFail()
                    return
                self.sm.signal(signal.SNN_RECEIVED, msg)
            elif self.sm.currentState() == state.SNN_SENT:  # handshake phase 2
                if not self.processHSSecond(msg):
                    self.authenticationFail()
                    return
                self.sm.signal(signal.ACK_RECEIVED, msg)
            elif self.sm.currentState() == state.SNN_RECV:  # handshake phase 3
                if not msg.AckFlag:
                    log(errType.HANDSHAKE, '3rd hs lost' + msg.Data)
                    self.transport.write(self.__lastPacket.__serialize__())
                    self.startTimer()
                    return
                if msg.SeqNum != self.__ackNum:
                    log(errType.TRANSMISSION, "seq num false ")
                    continue
                if not self.processHSThird(msg):
                    self.authenticationFail()
                    return
                self.sm.signal(signal.ACK_RECEIVED, msg)
            elif self.sm.currentState() == state.CLOSEREQ:
                if msg.SeqNum == self.__peerISN:
                    self.sm.signal(signal.CLOSE_ACK, "")
                else:
                    log(errType.TRANSMISSION,
                        'seqnum error when close {0} | {1} | {2} | {3}'.format(
                            msg.SeqNum, self.__peerISN, msg.CloseFlag, len(msg.Data)))
            elif self.sm.currentState() == state.ESTABLISHED:
                if msg.CloseFlag:
                    # log(errType.CHECK, 'recv close flag {0} | {1}'.format(
                    #     len(self.higherTransport.getDataBuf()), self.higherTransport.getTimer().started()))
                    if len(self.higherTransport.getDataBuf()) or self.higherTransport.getTimer().started():
                        callLater(1, self.processClose(), msg)
                    self.processClose(msg)
                elif msg.AckFlag:  # recv ack
                    if msg.SeqNum == self.__peerISN - 1:  # recv hs2
                        # log(errType.HANDSHAKE, 'recv 2nd hs when established')
                        self.transport.write(self.__lastPacket.__serialize__())
                    # log(errType.CHECK, 'recv ack flag')
                    self.higherTransport.stopTimer(msg.AckNum)
                else:  # recv data
                    if msg.SeqNum != self.__ackNum:
                        # log(errType.CHECK, '{0} | {1} | {2} | {3} | {4}'.format(
                        #     str(len(msg.Data)), str(self.__isClient),
                        #     str(msg.SeqNum), str(self.__ackNum),
                        #     str(self.__oneBeforeLastAck)))
                        if msg.SeqNum == self.__oneBeforeLastAck:
                            self.reSendLastPacket()
                            return
                        log(errType.TRANSMISSION, "seq num false")
                        continue
                    self.processData(msg)

    def processClose(self, msg):
        if msg.SeqNum == self.__peerISN - 1:
            self.sm.signal(signal.CLOSE_REQ, msg)
            self.transport.write(self.buildCloseAckPacket(msg).__serialize__())
            self.sm.signal(signal.CLOSE, msg)

    def processHSFirst(self, msg):  # server
        if not self.checkHSPacket(msg):
            return False
        self.__peerISN = msg.SeqNum + 1
        msgToSend = self.sendSHSPacket(msg)
        self.transport.write(msgToSend.__serialize__())
        self.__lastPacket = msgToSend
        self.startTimer()
        # log(errType.CHECK, 'HS 1st end, HS 2nd start')
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
        # log(errType.CHECK, 'HS 2nd end, HS 3rd start')
        return True

    def sendTHSPacket(self, msg):
        msgToSend = MyMessage()
        msgToSend.Cert = [intToNonce(int(msg.Cert[0], 16) + 1)]
        msgToSend.SeqNum = self.__initialSN + 1
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
        return True

    def processData(self, msg):
        self.__oneBeforeLastAck = msg.SeqNum
        packetToSent = self.buildAckPacket(msg)
        self.transport.write(packetToSent.__serialize__())
        self.__lastPacket = packetToSent
        self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

    def buildAckPacket(self, msg):
        msgToSend = MyMessage()
        msgToSend.SeqNum = self.__initialSN + 1
        self.__ackNum = msg.SeqNum + len(msg.Data)
        msgToSend.AckNum = self.__ackNum
        msgToSend.AckFlag = True
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def checkHSPacket(self, msg):
        cert1 = X509Certificate.loadPEM(msg.Cert[2 if self.__isClient else 1])
        cert2 = X509Certificate.loadPEM(msg.Cert[3 if self.__isClient else 2])
        peerPubKeyBlock = cert2.getPublicKeyBlob()
        self.peerPubKey = RSA.importKey(peerPubKeyBlock)
        # 0. Check signature
        if not self.checkSign(msg):
            return False
        # 1.server do check IP
        if cert1.getSubject()["commonName"] != self.transport.getPeer().host:
            self.log(errType.HANDSHAKE, "IP false")
            return False
        # 2, 3, 4: checkCerts
        res = checkCerts(cert1, cert2)
        if not res:
            log(errType.HANDSHAKE, "checkCerts false")
            return False
        if self.__isClient:
            # 5.public key check the signature of nonce1
            checkSignature = intToNonce(int(clientNonce, 16) + 1) == msg.Cert[1]
            if not checkSignature:
                log(errType.HANDSHAKE, "wrong nonce1")
                return False
        else:
            # get server's nonce
            if msg.SessionID[:len(msg.Cert[0])] != msg.Cert[0]:
                log(errType.HANDSHAKE, "wrong client nonce")
                return False
            self.serverNonce = msg.SessionID[len(msg.Cert[0]):]
        return True

    def checkTHSPacket(self, msg):
        if not intToNonce(int(self.serverNonce, 16) + 1) == msg.Cert[0]:
            log(errType.HANDSHAKE, "wrong signature")
            return False
        return True

    def buildCloseAckPacket(self, msg):
        msgToSend = MyMessage()
        msgToSend.SeqNum = self.__initialSN + 1
        self.__ackNum = msg.SeqNum + len(msg.Data)
        msgToSend.AckNum = self.__ackNum
        msgToSend.AckFlag = True
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def closeConnection(self):
        # log(errType.CHECK, '[CHECK] closing {0}'.format(self.__isClient))
        self.transport.write(self.buildClosePacket().__serialize__())
        self.sm.signal(signal.CLOSING, "")
        self.startTimer()

    def buildClosePacket(self):
        packet = MyMessage()
        packet.SeqNum = self.__initialSN
        packet.CloseFlag = True
        packet.Signature = buildSign(packet.__serialize__())
        return packet

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
        # log(errType.CHECK, 'authentication fail')
        self.initialize()
        self.transport.write(self.buildResetPacket().__serialize__())
        if self.__isClient:
            self.sm.signal(signal.SNN_SEND, "")

    def initialize(self):
        self.sm.signal(signal.RESET, "")
        self.__ackNum = 0
        self.__lastPacket = ""
        self.__buffer = ""

    def checkSign(self, msg):
        checkSignature = checkPacketSign(self.peerPubKey, msg)
        if not checkSignature:
            log(errType.HANDSHAKE, "signature false")
        return checkSignature


class MyServerFactory(StackingFactoryMixin, ServerFactory):
    def buildProtocol(self, addr):
        return RIProtocol()


# ------------------------------------------------------------------
# below are client

class MyClientFactory(StackingFactoryMixin, ClientFactory):
    def buildProtocol(self, addr):
        return RIProtocol(True)


# ------------------------------------------
# public functions

def checkCerts(cert1, cert2):
    # 2.check cert1's sign is the cert2's subject
    if cert1.getIssuer() != cert2.getSubject():
        log(errType.HANDSHAKE, 'cert sign wrong:')
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
        log(errType.HANDSHAKE, 'CA wrong')
        return False

    # 4.check cert2's sign is the root
    if cert2.getIssuer() != rootCert.getSubject():
        log(errType.HANDSHAKE, 'root sign wrong:')
        return False
    rootPublicKeyBlock = rootCert.getPublicKeyBlob()
    rootPublicKey = RSA.importKey(rootPublicKeyBlock)
    rootVerifier = PKCS1_v1_5.new(rootPublicKey)
    rootHasher = SHA256.new()
    CAdata = cert2.getPemEncodedCertWithoutSignatureBlob()
    rootHasher.update(CAdata)
    rootResult = rootVerifier.verify(rootHasher, cert2.getSignatureBlob())
    if not rootResult:
        log(errType.HANDSHAKE, 'root wrong')
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


def log(type, msg):
    if type == errType.CHECK or type == errType.TIMER:
        print '\x1b[6;30;42m[' + type + ']: ' + msg + '\x1b[0m'
    else:
        print '\x1b[6;30;41m[' + type + ']: ' + msg + '\x1b[0m'


ConnectFactory = MyClientFactory
ListenFactory = MyServerFactory
