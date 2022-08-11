from util import montgomery_reduce, barrett_reduce, cast_to_short

NTT_ZETAS = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628 ]

NTT_ZETAS_INV = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
    1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
    1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
    1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
    3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
    1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
    2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
    829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441 ]


def modq_mul_mont(a, b):
    """
    multiply a, b (assumed to be 16 bit signed short), then return montgom reduce
    :param a:
    :param b:
    :return: a*b reduced (short)
    """
    return montgomery_reduce(a * b)


def ntt(r):
    """
    in-place number theoretic transform (NTT, aka fourier transform)
    input is standard order
    output is bit-reversed
    :param r:
    :return:
    """
    j = 0
    k = 1
    l = 128
    while l >= 2:
        start = 0
        while start < 256:
            zeta = NTT_ZETAS[k]
            k = k + 1
            j = start
            while j < start + l:
                t = modq_mul_mont(zeta, r[j + l])
                r[j + l] = cast_to_short(r[j] - t)
                r[j] = cast_to_short(r[j] + t)
                j += 1
            start = j + l
        l >>= 1
    return r

def inv_ntt(r):
    j = 0
    k = 0
    l = 2
    while l <= 128:
        start = 0
        while start < 256:
            zeta = NTT_ZETAS_INV[k]
            k = k + 1
            j = start
            while j < (start + l):
                t = r[j]
                t_rjl = cast_to_short(t + r[j+l])
                r[j] = barrett_reduce(t_rjl)
                r[j+l] = cast_to_short(t - r[j+l])
                r[j+l] = modq_mul_mont(zeta, r[j+l])
                j += 1
            start = j + l
        l <<= 1
    for j in range(0,256):
        r[j] = modq_mul_mont(r[j], NTT_ZETAS_INV[127])
    return r

def base_multiplier(a0, a1, b0, b1, zeta):
    r = [ 0 for x in range(0,2)]
    r[0] = modq_mul_mont(a1, b1)
    r[0] = modq_mul_mont(r[0], zeta)
    r[0] = cast_to_short(r[0] + modq_mul_mont(a0,b0))
    r[1] = modq_mul_mont(a0, b1)
    r[1] = cast_to_short(r[1] + modq_mul_mont(a1, b0))
    return r
