import sys
from twisted.internet.protocol import ReconnectingClientFactory

from myProtocol import lab2stack
from playground.twisted.endpoints import GateClientEndpoint
from twisted.internet import reactor, protocol, stdio
from twisted.protocols.basic import LineReceiver


class httpClient(protocol.Protocol):
    def connectionMade(self):
        print("Higher Connection Made")

    def dataReceived(self, data):
        print(data)
        sys.stdout.write('>>>')
        sys.stdout.flush()

    def sendMsg(self, data):
        if data == "close":
            self.transport.loseConnection()
            return
        self.transport.write(data)

    def connectionLost(self, reason):
        print "connection lost"


class httpClientFactory(protocol.ClientFactory):
    global client

    def buildProtocol(self, addr):
        print client
        return client

    def clientConnectionFailed(self, connector, reason):
        print('Connection failed. Reason:', reason)
        reactor.stop()
        # ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)

    def clientConnectionLost(self, connector, reason):
        print('Lost connection.  Reason:', reason)
        reactor.stop()
        # ReconnectingClientFactory.clientConnectionLost(self, connector, reason)


class stdIO(LineReceiver):
    global client
    delimiter = '\n'

    def connectionMade(self):
        self.transport.write('>>>>')

    def lineReceived(self, line):
        client.sendMsg(line)


global client
client = httpClient()
stdio.StandardIO(stdIO())
endpoint = GateClientEndpoint.CreateFromConfig(reactor, '20164.1.3414.2414', 19090, 'gatekey1',
                                               networkStack=lab2stack)
endpoint.connect(httpClientFactory())
reactor.run()
