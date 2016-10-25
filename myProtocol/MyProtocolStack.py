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
from twisted.internet.protocol import Protocol, Factory

DEFAULT_WINDOW_SIZE = 5
DEFAULT_SEGMENT_SIZE = 2048

with open("./keys/20164_signed.cert") as f:
    rootCertData = f.read()
rootCert = X509Certificate.loadPEM(rootCertData)
priKey = RSA.importKey(CertFactory.getPrivateKeyForAddr("./keys/private.key"))

clientNonce = random.randint(0, 65535)
DEFAULT_CLIENT_SESSION = str(clientNonce) + str(random.randint(0, 65535))


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
        ("WindowSize", UINT1, DEFAULT_VALUE(DEFAULT_WINDOW_SIZE)),
        ("MaxSegSize", UINT4, DEFAULT_VALUE(DEFAULT_SEGMENT_SIZE)),
        ("CloseFlag", BOOL1, DEFAULT_VALUE(False)),
        ("SeqNumNotiFlag", BOOL1, DEFAULT_VALUE(False)),
        ("ResetFlag", BOOL1, DEFAULT_VALUE(False)),
        ("PushFlag", BOOL1, DEFAULT_VALUE(False)),
        ("Data", STRING, DEFAULT_VALUE("")),
        ("OPTIONS", LIST(STRING), DEFAULT_VALUE([]))
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
    ACK_RECEIVED = "Acknowledgement received"
    CLOSE = "Close"
    CLOSE_REQ = "Close request"
    CLOSE_ACK = "Close acknowledgement"
    # server
    SYN_RECEIVED = "Handshake syn flag received"


class errType(object):
    GENERAL = "General"
    HANDSHAKE = "Handshake"
    TRANSMISSION = "transmission"


# ----------------------------------
# server
class MyServerTransport(StackingTransport):
    # def __init__(self, lowerTransport, fixedKey):
    __data = ""

    def __init__(self, lowerTransport):
        StackingTransport.__init__(self, lowerTransport)
        self.__timer = threading.Timer(3, self.reSendDataPacket)

    def startTimer(self):
        self.__timer = threading.Timer(3, self.reSendDataPacket)
        self.__timer.start()

    def stopTimer(self):
        self.__timer and self.__timer.cancel()

    def reSendDataPacket(self):
        self.lowerTransport().write(self.__dataPacket)

    def write(self, packet):
        self.stopTimer()
        if isinstance(packet, str):
            self.__data = packet
            return
        else:
            packet.Data = self.__data
            packet.Signature = ""
            packet.Signature = buildSign(packet.__serialize__())
        self.lowerTransport().write(packet.__serialize__())
        not packet.PushFlag and self.startTimer()
        self.__dataPacket = packet.__serialize__()
        self.__data = ""


class MyServerProtocol(StackingProtocolMixin, Protocol):
    __serverInitialSN = random.randint(0, 1000)

    def __init__(self):
        self.sm = StateMachine("ServerStateMachine")
        self.__storage = MessageStorage()
        self.setupServerSM()

        with open("./keys/wli_signed.cert") as f:
            self.myCertData = f.read()
        with open("./keys/wenjunli_signed.cert") as f:
            self.CACertData = f.read()

        self.__buffer = ""  # for data received
        self.__bufCount = 0  # for count packet until it reachs WindowSize
        self.__dataBuf = ""  # store the data received
        self.__lastPacket = ""  # the last sent packet used when reset flag is true
        self.__timer = threading.Timer(3, self.reSendLastPacket)
        self.__dataPacketSeq = []  # store all the packet SeqNum received, used for check

    def setupServerSM(self):
        self.sm.addState(state.LISTENING, (signal.SYN_RECEIVED, state.SNN_RECV))
        self.sm.addState(state.SNN_RECV, (signal.ACK_RECEIVED, state.ESTABLISHED))
        self.sm.addState(state.ESTABLISHED, (signal.CLOSE_REQ, state.CLOSERECV))
        self.sm.addState(state.CLOSERECV, (signal.CLOSE, state.CLOSED))
        self.sm.addState(state.CLOSED, onEnter=self.onClose)
        self.sm.start(state.LISTENING)

    def onClose(self, signal, data):
        self.higherTransport.loseConnection()

    def connectionMade(self):
        self.higherTransport = MyServerTransport(self.transport)
        self.makeHigherConnection(self.higherTransport)

    def startTimer(self):
        self.__timer = threading.Timer(3, self.reSendLastPacket)
        self.__timer.start()

    def stopTimer(self):
        self.__timer and self.__timer.cancel()

    def reSendLastPacket(self):
        # print "[RESNED]"
        self.transport.write(self.__lastPacket)

    def dataReceived(self, data):
        self.stopTimer()
        # print self.transport.getHost()  # my IP
        self.__buffer += data
        while self.__buffer:
            msg, byte = MyMessage.Deserialize(self.__buffer)
            self.__storage.update(self.__buffer[:byte])
            self.__buffer = self.__buffer[byte:]
        for msg in self.__storage.iterateMessages():
            # after handshake phase 1, got clientPubKey, then authenticate
            if self.sm.currentState() != state.LISTENING:  # hasattr(self, 'clientPubKey'):
                if not self.checkSign(msg):
                    if self.sm.currentState() == state.ESTABLISHED:
                        # failed during data exchange
                        return
                    elif self.sm.currentState() == state.LISTENING or self.sm.currentState() == state.SNN_RECV:
                        self.higherTransport.write(self.buildResetPacket())
                        return
            if msg.ResetFlag:
                # print "[SERVER RESET]"
                self.processHSF(msg)
                pass
            elif self.sm.currentState() == state.LISTENING:  # handshake phase 1
                self.processHSFirst(msg)
            elif self.sm.currentState() == state.SNN_RECV:  # handshake phase 3
                self.processHSThird(msg)
            elif self.sm.currentState() == state.ESTABLISHED:
                if msg.CloseFlag:
                    print '[CLOSED]'
                    if msg.SeqNum == self.__clientISN:
                        self.sm.signal(signal.CLOSE_REQ, msg)
                        self.higherTransport.write(self.buildAckPacket(msg))
                        self.sm.signal(signal.CLOSE, msg)
                else:
                    # print "[CHECK] data received"
                    if msg.SeqNum < self.__lastAckNum:
                        # packet has received
                        # print "[PASS]"
                        try:
                            self.__dataPacketSeq.index(msg.SeqNum)
                        except Exception, e:
                            self.log(errType.TRANSMISSION, "fake packet")
                            self.higherTransport.write(self.buildAckPacket(msg, True))
                        continue
                    self.checkDataPacket(msg)
                    if msg.SeqNum > self.__lastAckNum:
                        # data packet in the middle lost
                        self.log(errType.TRANSMISSION, "packet lost")
                        self.higherTransport.write(self.buildAckPacket(msg, True))
                    else:
                        self.processData(msg)

    def processHSFirst(self, msg):
        self.checkFHSPacket(msg)
        self.setSize(msg.WindowSize, msg.MaxSegSize)
        if msg.SeqNumNotiFlag:
            self.__clientISN = msg.SeqNum + 1
        # print '[CHECK] phase 1 end'
        self.transport.write(self.sendSHSPacket(msg).__serialize__())
        self.__lastPacket = self.sendSHSPacket(msg).__serialize__()
        self.startTimer()
        self.sm.signal(signal.SYN_RECEIVED, msg)

    def processHSThird(self, msg):
        self.checkTHSPacket(msg)
        if msg.SeqNumNotiFlag:
            self.__clientISN = msg.SeqNum
        self.sm.signal(signal.ACK_RECEIVED, msg)
        self.__lastAckNum = self.__clientISN + self.segSize + 1
        print '[ESTABLISHED]'

    def processData(self, msg):
        self.__dataPacketSeq.append(msg.SeqNum)
        if self.__bufCount < self.windowSize:
            # not all data packets received
            self.__dataBuf += msg.Data
            self.__bufCount += 1
            self.__lastAckNum = msg.SeqNum + len(msg.Data) + 1
        if self.__bufCount == self.windowSize or msg.PushFlag:
            # have received all packets, send ack
            self.__bufCount = 0
            packetToSent = self.buildAckPacket(msg)
            if msg.PushFlag:
                self.higherProtocol() and self.higherProtocol().dataReceived(self.__dataBuf)
                self.initialize()
                packetToSent.PushFlag = True
            self.higherTransport.write(packetToSent)

    def initialize(self):
        # once a data has all received, wait for next input of client
        self.__lastAckNum = self.__clientISN + self.segSize + 1
        self.__dataBuf = ""

    def setSize(self, windowSize, segSize):
        self.windowSize = min(windowSize, DEFAULT_WINDOW_SIZE)
        self.segSize = min(segSize, DEFAULT_SEGMENT_SIZE)

    def checkFHSPacket(self, msg):
        clientCert1 = X509Certificate.loadPEM(msg.Cert[1])  # a.b.c.d
        clientCert2 = X509Certificate.loadPEM(msg.Cert[2])  # a.b.c
        # get client public key
        clientPubKeyBlock = clientCert2.getPublicKeyBlob()
        self.clientPubKey = RSA.importKey(clientPubKeyBlock)
        # 0. Check signature
        self.checkSign(msg)
        # 1.server do check IP
        if clientCert1.getSubject()["commonName"] != self.transport.getPeer()[0]:
            self.log(errType.HANDSHAKE, "IP false")
            self.terminate()
        # 2, 3, 4: checkCerts
        res = checkCerts(self, clientCert1, clientCert2)
        if not res:
            self.log(errType.HANDSHAKE, "checkCerts false")
            self.terminate()
        # get server's nonce
        if msg.SessionID[:len(msg.Cert[0])] != str(msg.Cert[0]):
            self.log(errType.HANDSHAKE, "wrong client nonce")
            self.terminate()
        self.serverNonce = int(msg.SessionID[len(msg.Cert[0]):])

    def sendSHSPacket(self, msg):
        msgToSend = MyMessage()
        msgToSend.SeqNum = self.__serverInitialSN
        msgToSend.SessionID = msg.SessionID[len(msg.Cert[0]):] + msg.SessionID[:len(msg.Cert[0])]
        msgToSend.AckNum = msg.SeqNum + 1
        msgToSend.AckFlag = True
        msgToSend.WindowSize = self.windowSize
        msgToSend.MaxSegSize = self.segSize
        msgToSend.Cert = [self.serverNonce, buildSign(str(int(msg.Cert[0]) + 1)), self.myCertData, self.CACertData]
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def checkTHSPacket(self, msg):
        deNonce = checkSign(self.clientPubKey, str(self.serverNonce + 1), msg.Cert[0])
        if not deNonce:
            self.log(errType.HANDSHAKE, "wrong signature")
            self.terminate()

    def checkDataPacket(self, msg):
        if msg.WindowSize != self.windowSize:
            self.log(errType.TRANSMISSION, "window size error")
            self.terminate()
        if msg.MaxSegSize != self.segSize:
            self.log(errType.TRANSMISSION, "segment size error")
            self.terminate()

    def buildAckPacket(self, msg, resetAck=False):
        msgToSend = MyMessage()
        self.__serverInitialSN += 1
        msgToSend.SeqNum = self.__serverInitialSN
        if resetAck:
            msgToSend.AckNum = self.__lastAckNum
        else:
            msgToSend.AckNum = msg.SeqNum + len(msg.Data) + 1
        msgToSend.AckFlag = True
        msgToSend.WindowSize = self.windowSize
        msgToSend.MaxSegSize = self.segSize
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def buildResetPacket(self):
        msgToSend = MyMessage()
        msgToSend.SeqNum = self.__serverInitialSN
        msgToSend.ResetFlag = True
        msgToSend.Cert = [self.myCertData, self.CACertData]
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def checkSign(self, msg):
        checkSignature = checkPacketSign(self.clientPubKey, msg)
        if not checkSignature:
            self.log(errType.HANDSHAKE, "signature false")
            self.terminate()
        return checkSignature

    def terminate(self):
        pass

    def log(self, type, msg):
        print '[' + type + ']: ' + msg


class MyServerFactory(StackingFactoryMixin, Factory):
    # FixedKey = "PASSWORD"
    protocol = MyServerProtocol


# ------------------------------------------------------------------
# below are client


class MyClientTransport(StackingTransport):
    __resendsSeq = [] # store currently sent packets' SeqNum
    __resendsValue = [] # store currently sent packets' data
    __lastAckNum = 0 # store the next AckNum, so if the received AckNum smaller than it, some packets should be resent

    def __init__(self, lowerTransport, initSeqNum, protocol):
        self.__initPacketSN = initSeqNum
        self.__protocol = protocol
        self.__timer = threading.Timer(3, self.reSendDataPacket, 0)
        StackingTransport.__init__(self, lowerTransport)

    def write(self, data):
        count = 1
        raw = []
        self.__dataValues = []
        self.__dataSeqs = []
        while data:
            raw.append([self.__initPacketSN + count * (self.segSize + 1), data[:self.segSize]])
            data = data[self.segSize:]
            count += 1
        raw.sort()
        for ele in raw:
            self.__dataSeqs.append(ele[0])
            self.__dataValues.append(ele[1])
        self.sendMsg(0)

    def loseConnection(self):
        self.lowerTransport().write(self.buildClosePacket(self.__initPacketSN).__serialize__())
        self.__protocol.setSMCloseReq()
        self.startTimer(1)

    def sendMsg(self, ackNum):
        self.stopTimer()
        self.__resendsSeq = []
        self.__resendsValue = []
        pushFlag = False
        if not ackNum:
            start = 0
        else:
            # print 'line 346:' + str(ackNum) + '--' + str(self.__lastAckNum)
            if ackNum < self.__lastAckNum:
                self.reSendDataPacket(ackNum)
                self.startTimer()
                return
            else:
                try:
                    start = self.__dataSeqs.index(ackNum)
                except Exception, e:
                    print e
        for i in range(start, start + self.windowSize):
            if i < len(self.__dataSeqs):
                if i == len(self.__dataSeqs) - 1:
                    pushFlag = True
                packet = self.buildDataPacket(self.__dataSeqs[i], self.__dataValues[i], pushFlag)
                self.__resendsSeq.append(self.__dataSeqs[i])
                self.__resendsValue.append(self.__dataValues[i])
                self.lowerTransport().write(packet.__serialize__())
        self.startTimer()
        self.__lastAckNum = start + self.windowSize < len(self.__dataSeqs) and self.__dataSeqs[start + self.windowSize]

    def startTimer(self, state=0):
        if state:
            self.__timer = threading.Timer(3, self.reSendClosePacket)
        else:
            self.__timer = threading.Timer(3, self.reSendDataPacket, 0)
        self.__timer.start()

    def stopTimer(self):
        self.__timer and self.__timer.cancel()

    def buildDataPacket(self, seq, data, push=False):
        packet = MyMessage()
        packet.SeqNum = seq
        packet.WindowSize = self.windowSize
        packet.MaxSegSize = self.segSize
        packet.Data = data
        packet.PushFlag = push
        packet.Signature = buildSign(packet.__serialize__())
        return packet

    def reSendDataPacket(self, ackNum):
        self.stopTimer()
        if not ackNum:
            t = 0
        else:
            t = self.__resendsSeq.index(ackNum)
        for i in range(t, self.windowSize):
            self.lowerTransport().write(
                self.buildDataPacket(self.__resendsSeq[i], self.__resendsValue[i]).__serialize__())
        self.startTimer()

    def reSendClosePacket(self):
        self.lowerTransport().write(self.buildClosePacket(self.__initPacketSN).__serialize__())
        self.startTimer(1)

    def buildClosePacket(self, seqNum):
        packet = MyMessage()
        packet.SeqNum = seqNum
        packet.CloseFlag = True
        packet.WindowSize = self.windowSize
        packet.MaxSegSize = self.segSize
        packet.Signature = buildSign(packet.__serialize__())
        return packet

    def setSize(self, windowSize, segSize):
        self.windowSize = windowSize
        self.segSize = segSize


class MyClientProtocol(StackingProtocolMixin, Protocol):
    __clientInitialSN = random.randint(0, 1000)

    def __init__(self):
        self.__storage = MessageStorage()
        self.__buffer = ""
        self.__dataBuf = ""

        self.sm = StateMachine("ClientStateMachine")
        self.setupClientSM()
        # self.__timer = threading.Timer(3, self.resendHS, self.sm.currentState())

        certs = CertFactory.getCertsForAddr(["./keys/wli_signed.cert", "./keys/wenjunli_signed.cert"])
        self.myCertData = certs[0]
        self.CACertData = certs[1]

    def setupClientSM(self):
        self.sm.addState(state.SNN_SENT, (signal.ACK_RECEIVED, state.ESTABLISHED))
        self.sm.addState(state.ESTABLISHED, (signal.CLOSE, state.CLOSEREQ), onEnter=self.onEstablished)
        self.sm.addState(state.CLOSEREQ, (signal.CLOSE_ACK, state.CLOSED))
        self.sm.addState(state.CLOSED, onEnter=self.onClose)

    def onEstablished(self, signal, data):
        print '[ESTABLISHED]'
        self.higherTransport = MyClientTransport(self.transport, self.__clientInitialSN + 1, self)
        self.higherTransport.setSize(data.WindowSize, data.MaxSegSize)
        self.makeHigherConnection(self.higherTransport)

    def onClose(self, signal, data):
        print '[CLOSED]'
        self.transport.loseConnection()
        self.higherProtocol().connectionLost("normal end")
        # self.higherTransport.loseConnection()

    def startTimer(self):
        self.__timer = threading.Timer(3, self.resendHS, self.sm.currentState())
        self.__timer.start()

    def stopTimer(self):
        self.__timer and self.__timer.cancel()

    def resendHS(self, cState):
        if cState == state.SNN_SENT:
            self.sendFHSPacket()

    def connectionMade(self):
        self.sendFHSPacket()

    def sendFHSPacket(self):
        self.transport.write(self.buildFHSPacket().__serialize__())
        self.sm.start(state.SNN_SENT)
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
        # print self.transport.getHost()  # my IP
        self.__buffer += data
        while self.__buffer:
            msg, byte = MyMessage.Deserialize(self.__buffer)
            self.__storage.update(self.__buffer[:byte])
            self.__buffer = self.__buffer[byte:]
        for msg in self.__storage.iterateMessages():
            if hasattr(self, 'serverPubKey'):
                if not self.checkSign(msg):
                    # self.sm.start(state.INITIATING)
                    self.higherTransport.write(self.buildResetPacket())
                    return
            if msg.ResetFlag:
                print "[CLIENT RESET]"
                self.connectionMade()
            elif self.sm.currentState() == state.SNN_SENT:
                self.processHSSecond(msg)
            elif self.sm.currentState() == state.CLOSEREQ:
                self.sm.signal(signal.CLOSE_ACK, "")
            else:
                if msg.Data:
                    self.__dataBuf += msg.Data
                if msg.PushFlag:
                    self.higherProtocol() and self.higherProtocol().dataReceived(self.__dataBuf)
                    self.initialize()
                else:
                    self.higherTransport.sendMsg(msg.AckNum)

    def processHSSecond(self, msg):
        self.stopTimer()
        self.checkSHSPacket(msg)
        msgToSend = self.sendTHSPacket(msg)
        self.transport.write(msgToSend.__serialize__())  # try to transport my msg
        self.sm.signal(signal.ACK_RECEIVED, msg)
        print '[CHECK] client shakehand end'

    def initialize(self):
        self.__dataBuf = ""
        self.higherTransport.stopTimer()

    def buildResetPacket(self):
        msgToSend = self.buildFHSPacket()
        msgToSend.ResetFlag = True
        msgToSend.Signature = ""
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def checkSHSPacket(self, msg):
        serverCert1 = X509Certificate.loadPEM(msg.Cert[2])  # a.b.c.d
        serverCert2 = X509Certificate.loadPEM(msg.Cert[3])  # a.b.c
        # get server public key
        serverPubKeyBlock = serverCert2.getPublicKeyBlob()
        self.serverPubKey = RSA.importKey(serverPubKeyBlock)
        # 0. Check signature
        self.checkSign(msg)
        # 1.server do check IP
        if serverCert1.getSubject()["commonName"] != self.transport.getPeer()[0]:
            self.log(errType.HANDSHAKE, "IP false")
            self.terminate()
        # 2, 3, 4: checkCerts
        res = checkCerts(self, serverCert1, serverCert2)
        if not res:
            self.log(errType.HANDSHAKE, "checkCerts false")
            self.terminate()
        # 5.public key check the signature of nonce1
        checkSignature = checkSign(self.serverPubKey, str(clientNonce + 1), msg.Cert[1])
        if not checkSignature:
            self.log(errType.HANDSHAKE, "wrong nonce1")
            self.terminate()

    def sendTHSPacket(self, msg):
        msgToSend = MyMessage()
        msgToSend.Cert = [buildSign(str(int(msg.Cert[0]) + 1))]
        msgToSend.SeqNum = self.__clientInitialSN + 1
        # msgToSend.SeqNumNotiFlag = True
        msgToSend.SessionID = DEFAULT_CLIENT_SESSION
        msgToSend.AckNum = msg.SeqNum + 1
        msgToSend.AckFlag = True
        msgToSend.Signature = buildSign(msgToSend.__serialize__())
        return msgToSend

    def checkSign(self, msg):
        checkSignature = checkPacketSign(self.serverPubKey, msg)
        if not checkSignature:
            self.log(errType.HANDSHAKE, "signature false")
            self.terminate()
        return checkSignature

    def setSMCloseReq(self):
        self.sm.signal(signal.CLOSE, "")

    def log(self, type, msg):
        print '[' + type + ']: ' + msg

    def terminate(self):
        pass


class MyClientFactory(StackingFactoryMixin, Factory):
    protocol = MyClientProtocol


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


ConnectFactory = MyClientFactory
ListenFactory = MyServerFactory
