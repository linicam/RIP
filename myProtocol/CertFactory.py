def getPrivateKeyForAddr(addr = "./keys/private.key"):
    with open(addr) as f:
        return f.read()

def getCertsForAddr(addr = ["./keys/wli_signed.cert", "./keys/wenjunli_signed.cert"]):
    chain = []
    with open(addr[0]) as f:
        chain.append(f.read())
    with open(addr[1]) as f:
        chain.append(f.read())
    return chain