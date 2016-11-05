from myProtocol import lab2stack
from playground.twisted.endpoints import GateServerEndpoint
from twisted.internet import reactor, protocol, stdio
from twisted.protocols.basic import LineReceiver

global server


class httpServer(protocol.Protocol):
    def __init__(self):
        pass

    def sendMsg(self, data):
        print '>>>', data
        if data == "close":
            self.transport.loseConnection()
            return
        # print data
        self.transport.write(data)

    def dataReceived(self, data):
        print '<<<' + data
        self.transport.write(data)

    def connectionLost(self, reason):
        print "[SERVER] connection lost"
        # reactor.stop()


class httpServerFactory(protocol.Factory):
    def __init__(self):
        pass

    global server

    def buildProtocol(self, addr):
        return server

    def clientConnectionFailed(self, connector, reason):
        print('Connection failed. Reason:', reason)
        reactor.stop()
        # ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)

    def clientConnectionLost(self, connector, reason):
        print('Lost connection.  Reason:', reason)
        reactor.stop()


class stdIO(LineReceiver):
    global server
    delimiter = '\n'

    def connectionMade(self):
        pass
        # self.transport.write('>>>>')

    def lineReceived(self, line):
        server.sendMsg(line)


server = httpServer()
stdio.StandardIO(stdIO())
endpoint = GateServerEndpoint.CreateFromConfig(reactor, 19090, 'gatekey1', networkStack=lab2stack)
endpoint.listen(httpServerFactory())
reactor.run()


# factory = protocol.ServerFactory()
#
# factory.protocol = httpServer
#
# reactor.listenTCP(80, factory)
