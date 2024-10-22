from app01.encrypt import rsa,prime

def elgamal():
    q = int(prime.makeprime(512),2)
    p = 2*q+1
    # p = 26598744311996291045717037233193337237416594846430652624064682976423067406579503903915094698628810803546270054481399123029735312130498391523990261518242499
    print(p)
    # while(prime.miller(bin(p))==0):
    #     q = int(prime.makeprime(512), 2)
    #     p = 2 * q + 1
    #     print(q)
    a = int(prime.makeprime(256),2)
    while(rsa.momi(a,2,p)==1 or rsa.momi(a,q,p)==1):
        a = int(prime.makeprime(256),2)
    d = int(prime.makeprime(448),2)
    y = rsa.momi(a,d,p)
    k = int(prime.makeprime(384),2)
    return [p,a,y,d,k]
def en_elgamal(m,p,a,y,d,k):
    u = rsa.momi(y, k, p)
    c1 = rsa.momi(a, k, p)
    c2 = u * m % p
    c = hex(c1) + ' ' + hex(c2)
    return c

def de_elgamal(c,d,p):
    c1,c2 = c.split(sep=' ')
    print(c1,c2)
    v = rsa.momi(int(c1,16),d,p)
    m = int(c2,16)/v
    return m
a = elgamal()
f = en_elgamal(50,a[0],a[1],a[2],a[3],a[4])
print(f)
g = de_elgamal(f,a[3],a[0])
print(g)




