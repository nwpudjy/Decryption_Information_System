import random
import datetime

def prime(n):
    p = []
    p.append('1')
    for i in range(n-2):
        a = random.choice(['0','1'])
        p.append(a)
    p.append('1')
    p = ''.join(p)
    return p

def momi(a,p):
    s = 1
    t = a
    m = bin(int(p,2) - 1)[2:]
    for i in m[::-1]:
        if i=='1':
            s *= t
        t *= t
        t %= int(p,2)
        s %= int(p,2)
    return s

def miller(p):
    for i in range(50):
        t = random.randint(1,int(p,2))
        if momi(t,p) != 1:
            return 0
    return 1
def makeprime(n):
    while(1):
        p = prime(n)
        if miller(p) == 1:
            return p



