def getPrivateKeyForAddr(addr):
    with open("/home/linicam/network/en600424lab2/myProtocol/keys/private.key") as f:
        return f.read()


def getCertsForAddr(addr):
    addr = ["/home/linicam/network/en600424lab2/myProtocol/keys/wli_signed.cert",
            "/home/linicam/network/en600424lab2/myProtocol/keys/wenjunli_signed.cert"]
    chain = []
    with open(addr[0]) as f:
        chain.append(f.read())
    with open(addr[1]) as f:
        chain.append(f.read())
    return chain


def getRootCert(addr="/home/linicam/network/en600424lab2/myProtocol/keys/20164_signed.cert"):
    with open(addr) as f:
        return f.read()
