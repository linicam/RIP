from myProtocol import lab2stack
from playground.twisted.endpoints import GateServerEndpoint
from twisted.internet import protocol
from twisted.internet import reactor

responseBody = '''HTTP/1.1 404 Not Found
Transfer-Encoding: chunked
Content-Type: text/html'''


class httpServer(protocol.Protocol):
    def __init__(self):
        pass

    def dataReceived(self, data):
        print 'success:' + data
        self.transport.write(data)

    def connectionLost(self, reason):
        print reason

class httpServerFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return httpServer()


def main():
    endpoint = GateServerEndpoint.CreateFromConfig(reactor, 19090, 'gatekey1', networkStack=lab2stack)
    endpoint.listen(httpServerFactory())
    reactor.run()


if __name__ == '__main__':
    main()
    # factory = protocol.ServerFactory()
    #
    # factory.protocol = httpServer
    #
    # reactor.listenTCP(80, factory)
