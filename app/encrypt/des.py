def bin_char(dec):
    list_bin = [dec[i:i + 8] for i in range(0, len(dec), 8)]
    list_int = []
    for bin_s in list_bin:
        list_int.append(int(bin_s, 2))
    try:
        ans = bytes(list_int).decode()
    except:
        ans = '秘钥错误'
    return ans
def char_b(text):
    b_text = text.encode()
    list_b_text = list(b_text)
    re = []
    for num in list_b_text:
        re.append(bin(num)[2:].zfill(8))

    bin_str = ''.join(re)
    return bin_str
def DES(text,f,cyber):
    # 初始置换IP
    IP = [[58, 50, 42, 34, 26, 18, 10, 2],
          [60, 52, 44, 36, 28, 20, 12, 4],
          [62, 54, 46, 38, 30, 22, 14, 6],
          [64, 56, 48, 40, 32, 24, 16, 8],
          [57, 49, 41, 33, 25, 17, 9, 1],
          [59, 51, 43, 35, 27, 19, 11, 3],
          [61, 53, 45, 37, 29, 21, 13, 5],
          [63, 55, 47, 39, 31, 23, 15, 7]]
    # 逆初始置换
    IP_1 = [[40, 8, 48, 16, 56, 24, 64, 32],
            [39, 7, 47, 15, 55, 23, 63, 31],
            [38, 6, 46, 14, 54, 22, 62, 30],
            [37, 5, 45, 13, 53, 21, 61, 29],
            [36, 4, 44, 12, 52, 20, 60, 28],
            [35, 3, 43, 11, 51, 19, 59, 27],
            [34, 2, 42, 10, 50, 18, 58, 26],
            [33, 1, 41, 9, 49, 17, 57, 25]]

    # 扩展变换E
    E = [[32, 1, 2, 3, 4, 5],
         [4, 5, 6, 7, 8, 9],
         [8, 9, 10, 11, 12, 13],
         [12, 13, 14, 15, 16, 17],
         [16, 17, 18, 19, 20, 21],
         [20, 21, 22, 23, 24, 25],
         [24, 25, 26, 27, 28, 29],
         [28, 29, 30, 31, 32, 1]]

    # P置换
    P = [[16, 7, 20, 21], [29, 12, 28, 17],
         [1, 15, 23, 26], [5, 18, 31, 10],
         [2, 8, 24, 14], [32, 27, 3, 9],
         [19, 13, 30, 6], [22, 11, 4, 25]]
    # S盒
    S_Box = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]
    # 置换选择1
    PC1 = [[57, 49, 41, 33, 25, 17, 9],
           [1, 58, 50, 42, 34, 26, 18],
           [10, 2, 59, 51, 43, 35, 27],
           [19, 11, 3, 60, 52, 44, 36],
           [63, 55, 47, 39, 31, 23, 15],
           [7, 62, 54, 46, 38, 30, 22],
           [14, 6, 61, 53, 45, 37, 29],
           [21, 13, 5, 28, 20, 12, 4]]
    # 置换选择2
    PC2 = [[14, 17, 11, 24, 1, 5],
           [3, 28, 15, 6, 21, 10],
           [23, 19, 12, 4, 26, 8],
           [16, 7, 27, 20, 13, 2],
           [41, 52, 31, 37, 47, 55],
           [30, 40, 51, 45, 33, 48],
           [44, 49, 39, 56, 34, 53],
           [46, 42, 50, 36, 29, 32]]
    # 循环左移位数
    LFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # 轮秘钥生成
    Key1 = cyber  # 秘钥
    if len(cyber)!=8:
        return "秘钥长度必须为8"
    key1 = list(Key1.encode())
    r_k = []
    for i in key1:
        r_k.append(bin(i)[2:].zfill(8))
    r_k = ''.join(r_k)
    key_PC = []  # 置换选择1
    for i in range(8):
        for j in range(7):
            key_PC.append(r_k[PC1[i][j] - int('1')])
    key_PC = ''.join(key_PC)  # 置换选择1完成
    C = key_PC[0:28]
    D = key_PC[28:56]

    # 循环左移
    def str_rol(s, k):
        tt = k % len(s)
        return s[tt:] + s[:tt]

    K = []
    for i in LFT:
        C = str_rol(C, i)
        D = str_rol(D, i)
        CD = C + D
        # 置换选择2
        CD_p = []
        for j in range(8):
            for k in range(6):
                CD_p.append(CD[PC2[j][k] - int('1')])
        CD_p = ''.join(CD_p)
        K.append(CD_p)

    ############################

    def de_encrypt(st1, K):
        str_IP = []  # 初始置换后的数组

        for i in range(8):  # 进行初始置换
            for j in range(8):
                str_IP.append(st1[IP[i][j] - int('1')])
        str_IP = ''.join(str_IP)  # 初始置换完成
        L = str_IP[0:32]
        R = str_IP[32:64]
        for lun in range(16):
            # F变换#############################
            # 扩展变化E
            str_E = []
            for i in range(8):
                for j in range(6):
                    str_E.append(R[E[i][j] - int('1')])
            str_E = ''.join(str_E)  # 完成扩展变换E
            or_E = []
            for i in range(48):
                or_E.append(str(int(str_E[i]) ^ int(K[lun][i])))
            or_E = ''.join(or_E)  # 与轮秘钥完成异或

            sp = 0
            S_E = []
            for i in range(8):
                s_p = or_E[sp:sp + 6]
                sp += 6
                lstr = s_p[0] + s_p[5]
                rstr = s_p[1:5]
                l = int(lstr[0]) * 2 + int(lstr[1]) * 1
                r = int(rstr[0]) * 8 + int(rstr[1]) * 4 + int(rstr[2]) * 2 + int(rstr[3]) * 1
                sl = S_Box[i][l]
                S_E.append(str(bin(sl[r])[2:].zfill(4)))
            S_E = ''.join(S_E)  # 完成S盒代替

            P_E = []
            for i in range(8):
                for j in range(4):
                    P_E.append(S_E[P[i][j] - int('1')])
            P_E = ''.join(P_E)  # 完成P置换
            # print(P_E)
            #####################################
            # L与R异或
            lin_R = []
            for i in range(32):
                lin_R.append(str(int(L[i]) ^ int(P_E[i])))
            lin_R = ''.join(lin_R)

            if lun < 15:
                L = ''.join(R)
                R = ''.join(lin_R)
            else:
                L = ''.join(lin_R)
        # 逆初始置换
        LR = L + R
        Ency = []
        for i in range(8):
            for j in range(8):
                Ency.append(LR[IP_1[i][j] - int('1')])
        Ency = ''.join(Ency)
        return Ency

    ###########################
    if f == 1 or f == 3:
        #################
        # 字符串转二进制
        bin_str = char_b(text)

        clen = int(len(bin_str) / 64)
        enc = []
        length = 0
        while length <= clen:
            st = bin_str[0 + 64 * length:64 + 64 * length]  # 原始串
            if len(st) < 64:  # 补齐64位
                st = st.zfill(64)
            en = de_encrypt(st, K)
            enc.append(en)
            length += 1
        enc = ''.join(enc)
        return enc
    if f == 2:
        dec = []
        K1 = K[::-1]
        length = 0
        clen = int(len(text) / 64)
        while length < clen:
            en = text[0 + 64 * length:64 + 64 * length]
            de = de_encrypt(en, K1)
            if length == clen-1:
                while de[0:8]=='00000000':
                    de = de[8:]
            dec.append(de)
            length += 1
        dec = ''.join(dec)
        ############################
        # 二进制转字符串
        return bin_char(dec)
        ##############################