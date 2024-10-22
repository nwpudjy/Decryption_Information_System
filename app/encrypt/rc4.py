def RC4(cyber, text):
    #S表
    S = []
    #R表
    R = []
    #秘钥K
    K = cyber
    for i in range(256):
        S.append(i)
        R.append(K[i%len(K)])
    J = 0
    for i in range(255):
        J = (J + S[i] + R[i])%256
        t = S[i]
        S[i] = S[J]
        S[J] = t
    length = len(text)
    I = 0
    J = 0
    key = []
    for x in range(length):
        I = (I+1)%256
        J = (J+S[I])%256
        t = S[I]
        S[I] = S[J]
        S[J] = t
        h = (S[I]+S[J])%256
        z = S[h]
        key.append(z)
    return key



