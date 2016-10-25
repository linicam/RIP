def getPrivateKeyForAddr(addr):
    with open(addr) as f:
        return f.read()

def getCertsForAddr(addr):
    chain = []
    with open(addr[0]) as f:
        chain.append(f.read())
    with open(addr[1]) as f:
        chain.append(f.read())
    return chain