S_BOX = [[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
         [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
         [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
         [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
         [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
         [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
         [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
         [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
         [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
         [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
         [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
         [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
         [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
         [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
         [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
         [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
S_BOX1 = [
    [0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb],
	[0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb],
	[0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e],
	[0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25],
	[0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92],
	[0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84],
	[0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06],
	[0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b],
	[0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73],
	[0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e],
	[0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b],
	[0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4],
	[0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f],
	[0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef],
	[0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61],
	[0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d],
]
#轮常量
Rcon = [
    ['01','02','04','08','10','20','40','80','1b','36'],
    ['00','00','00','00','00','00','00','00','00','00'],
    ['00','00','00','00','00','00','00','00','00','00'],
    ['00','00','00','00','00','00','00','00','00','00'],
]

#常规矩阵
CJ = [['02','03','01','01'],['01','02','03','01'],['01','01','02','03'],['03','01','01','02']]
CJ_1 = [
    ['0e','0b','0d','09'],
    ['09','0e','0b','0d'],
    ['0d','09','0e','0b'],
    ['0b','0d','09','0e'],
]

def change_16(a):
    str_en = []
    for i in range(int(len(a) / 4)):
        s = a[i * 4:i * 4 + 4]
        m = 8
        sum = 0
        for j in s:
            sum += (int(j) - 0) * m
            m = int(m / 2)
        r = hex(sum)[2:]
        str_en.append(r)
    str_en = ''.join(str_en)
    return str_en

def change_2(b):
    str_de = []
    for i in b:
        if i>='a':
            m = ord(i) - ord('a') + 10
        else:
            m = ord(i) - ord('0')
        str_de.append(bin(m)[2:].zfill(4))
    str_de = ''.join(str_de)
    return str_de
#行列转置
def changelr(s):
    t = []
    for i in range(4):
        for j in range(4):
            t.append(s[i*2+j*8:i*2+j*8+2])
    return ''.join(t)



#小S盒变换
def subbytes(s1,box):
    a = int(s1[0], base = 16)
    b = int(s1[1], base = 16)
    return hex(box[a][b])[2:].zfill(2)

#16进制字符异或
def mo_r(s1,s2):
    hex_1 = int(s1, base=16)
    hex_2 = int(s2, base=16)
    return hex(hex_1 ^ hex_2)[2:].zfill(2)

def str_rol(s, k):
    tt = k % len(s)
    return s[tt:] + s[:tt]

#秘钥扩展
def keymax(cyber):
    dp = [['0'] * 44 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            dp[i][j] = ''.join(cyber[i*8+j*2:i*8+j*2+2])
    lun = 0
    for i in range(44):
        if i>=4:
            if i%4!=0:
                for j in range(4):
                    # key_l.append(mo_r(cyber[j*4+(i-4)*2:j*4+(i-4)*2+2],cyber[j*4+(i-1)*2:j*4+(i-1)*2+2]))
                    dp[j][i] = ''.join(mo_r(dp[j][i-4],dp[j][i-1]))
            else:
                lin_s = []#W(i-1)
                lin_ss = []#W(i-4)

                for j in range(4):
                    lin_s.append(dp[j][i-1])
                    lin_ss.append(dp[j][i-4])
                lin_s = str_rol(lin_s,1)#字循环
                lin_s1 = []
                for j in lin_s:#字节代换
                    lin_s1.append(subbytes(j,S_BOX))
                lin_s2 = []
                for j in range(4):
                    lin_s2.append(mo_r(lin_ss[j],lin_s1[j]))#轮常量异或
                    dp[j][i] = ''.join(mo_r(lin_s2[j],Rcon[j][lun]))
                lun += 1


    return dp

# 字符串转二进制
def subbin(text):
    b_text = text.encode()
    list_b_text = list(b_text)
    re = []
    for num in list_b_text:
        re.append(bin(num)[2:].zfill(8))
    return ''.join(re)

def o_r(s1,s2):
    rou = []
    for i in range(16):
        st_1 = s1[i * 2:i * 2 + 2]
        st_2 = s2[i * 2:i * 2 + 2]
        hex_1 = int(st_1, base=16)
        hex_2 = int(st_2, base=16)
        t = hex(hex_1 ^ hex_2)[2:].zfill(2)
        rou.append(t)
    return rou

#取每轮的秘钥矩阵
def qunkey(i,dp):
    s = []
    for j in range(4):
        for k in range(4):
            s.append(dp[j][k+i*4])
    return ''.join(s)

#字节运算（S盒变换）
def SubBytes(s,box):
    s1 = [['0'] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            s1[i][j] = ''.join(subbytes(s[i*4+j],box))
    return s1

#左移
def leftmove(s):
    s += '0'
    return ''.join(s)[1:9]

#2进制字符异或
def mo_r2(s1,s2):
    t = []
    for i in range(8):
        t.append(str(int(s1[i])^int(s2[i])))
    return ''.join(t)

#02*s
def s_02(s_2):
    if s_2[0] == '1':
        s_2 = mo_r2(leftmove(s_2), '00011011')
    else:
        s_2 = leftmove(s_2)
    return s_2


#行移位
def ShiftRows(s,f):
    t = []
    for i in range(4):
        if f==1:
            p = -i
        else:p = i
        t.append(str_rol(s[i],p))
    return t

#列混合
def MixColumns(s):
    #乘法
    def multiply(s1,s2):
        s_2 = bin(int(s2, base=16))[2:].zfill(8)
        if s1 == '02':
            return s_02(s_2)
        elif s1 == '03':
            return mo_r2(s_02(s_2),s_2)
        else:
            return s_2
    s_mc = []
    for i in range(4):
        for j in range(4):
            s_md = []
            for k in range(4):
                s_md.append(multiply(CJ[i][k],s[k][j]))
            s_mc.append(change_16(mo_r2(s_md[3],mo_r2(s_md[2],mo_r2(s_md[0],s_md[1])))))

    return s_mc
#逆列混合
def InMixColumns(s):
    #乘法
    def multiply(s1,s2):
        s_2 = bin(int(s2, base=16))[2:].zfill(8)
        if s1 == '02':
            return s_02(s_2)
        elif s1 == '03':
            return mo_r2(s_02(s_2),s_2)
        elif s1 == '01':
            return s_2
        elif s1 == '0d':
            return mo_r2(mo_r2(s_02(multiply('04',s2)),s_02(multiply('02',s2))),s_2)
        elif s1 == '04':
            return s_02(s_02(s_2))
        elif s1 == '0e':
            return mo_r2(mo_r2(s_02(multiply('04',s2)),s_02(multiply('02',s2))), s_02(s_2))
        elif s1 == '0b':
            return mo_r2(mo_r2(s_02(multiply('04',s2)),s_02(s_2)), s_2)
        elif s1 == '09':
            return mo_r2(s_02(multiply('04',s2)),s_2)


    s_mc = []
    for i in range(4):
        for j in range(4):
            s_md = []
            for k in range(4):
                s_md.append(multiply(CJ_1[i][k],s[k][j]))
            s_mc.append(change_16(mo_r2(s_md[3],mo_r2(s_md[2],mo_r2(s_md[0],s_md[1])))))

    return s_mc



#轮秘钥加
def AddRoundKey(i,s,dp,f):
    key = ''.join(qunkey(i,dp))
    t = []
    if i == 10 and f==0:
        for j in range(4):
            for k in range(4):
                t.append(s[j][k])
        t = ''.join(t)
    elif i==0 and f==1:
        t = ''.join(s)
    else:
        t = ''.join(s)
    return o_r(key,t)


def AES_Encrypt(bin_str,cyber):
    dp = keymax(cyber)

    clen = int(len(bin_str) / 32)
    enc = []
    length = 0
    rou = ''
    aa = []
    while length <= clen:
        st = bin_str[32 * length:32 + 32 * length]  # 原始串
        if len(st) < 32:  # 补齐128位
            st = st.zfill(32)
        print('98888',st)
        st = changelr(st)
        print('明文：', st)
        cyber = qunkey(0, dp)  # W[0:3]
        rou = o_r(st, cyber)  # 第一个轮秘钥加
        # print("首先轮秘钥加：",rou)
        for lun in range(10):
            rou = SubBytes(rou, S_BOX)  # 字节运算
            # print(lun,'lun字节运算',rou)
            rou = ShiftRows(rou, 0)  # 行移位
            # print(lun, 'lun行移位', rou)
            if lun < 9:
                rou = MixColumns(rou)  # 列混合
                # print(lun, 'lun列混合', rou)
            rou = AddRoundKey(lun + 1, rou, dp, 0)  # 轮秘钥加
            # print(lun, 'lun轮秘钥加', rou)
        aa.append(''.join(rou))
        length += 1
    return aa


def AES_Decrypt(bin_str,cyber):
    print(bin_str)
    dp = keymax(cyber)
    clen = int(len(bin_str) / 32)
    enc = []
    length = 0
    while length < clen:
        st = bin_str[32*length:32*length+32]
        # st = changelr(st)
        print('密文：',length,' ', st)
        rou = []
        for i in range(16):
            rou.append(st[i * 2:i * 2 + 2])
        for lun in range(10):
            print(lun)
            rou = AddRoundKey(10 - lun, rou, dp, 1)  # 轮秘钥加
            rou_1 = []
            for i in range(4):
                rou_1.append(rou[i * 4:i * 4 + 4])
            rou = rou_1
            if lun > 0:
                rou = InMixColumns(rou)  # 列混合
                rou_1 = []
                for i in range(4):
                    rou_1.append(rou[i * 4:i * 4 + 4])
                rou = rou_1
            rou = ShiftRows(rou, 1)  # 行移位
            rou_2 = []
            for i in rou:
                for j in i:
                    rou_2.append(j)
            rou = rou_2
            rou = SubBytes(rou, S_BOX1)  # 字节运算
            rou_2 = []
            for i in rou:
                for j in i:
                    rou_2.append(j)
            rou = rou_2
        cyber = qunkey(0, dp)  # W[0:3]
        rou = ''.join(o_r(''.join(rou), cyber))  # 第一个轮秘钥加
        rou = changelr(rou)
        while rou[0:2]=='00':
            rou = rou[2:]
        print(rou)
        enc.append(rou)
        length += 1
    return enc
