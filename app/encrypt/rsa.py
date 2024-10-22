import random
from app01.encrypt import prime

def momi(a,p,g):
    s = 1
    t = a
    m = bin(p)[2:]
    for i in m[::-1]:
        if i=='1':
            s *= t
        t *= t
        t %= g
        s %= g
    return s


def husu(a,b):
    if prime.miller(bin(a)[2:]) == 0:
        return 1
    if b%a==0:
        return 1
    return 0

def put_p_q(n):
    p = prime.makeprime(n)
    q = prime.makeprime(n)
    while p==q:
        q = prime.makeprime(n)
    n = int(p, 2) * int(q, 2)
    fi = (int(p, 2) - 1) * (int(q, 2) - 1)
    e = random.randint(2,fi-1)
    while(husu(e,fi) == 1):
        e = random.randint(2,fi-1)

    return [p,q,fi,e,n]


def put_d(e,fi):
    l = []
    t = fi
    while(e!=1 and e>0):
        m = e
        l.append(int(t/e))
        e = t-int(t/e)*e
        t = m
    t = len(l)
    b = [1,l[t-1]]
    for i in range(t+1):
        if i > 1:
            b.append(b[i-1]*l[t-i]+b[i-2])
    if t%2 == 0:
        return b[t]
    else:
        return fi - b[t]

