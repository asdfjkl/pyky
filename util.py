from params import KYBER_POLY_BYTES, KYBER_N, KYBER_ETAK512, KYBER_ETAK768_1024, KYBER_Q_INV, KYBER_Q

def cast_to_short(x):
    y = x & 0xffff
    if y >= 2**15:
        y -= 2**16
    return y

def cast_to_int32(x):
    y = x & 0xffffffff
    if y >= 2**31:
        y -= 2**32
    return y

def cast_to_long64(x):
    y = x & 0xffffffffffffffff
    if y >= 2**63:
        y -= 2**64
    return y

def cast_to_byte(x):
    y = x & 0xff
    if y >= 2**7:
        y -= 2**8
    return y

def convert_byte_to_32_bit_unsigned_int(x):
    r = x[0] & 0xff # to mask negative values
    r |= (x[1] & 0xff) << 8
    r |= (x[2] & 0xff) << 16
    r |= (x[3] & 0xff) << 24
    return r

def convert_byte_to_24_bit_unsigned_int(x):
    r = x[0] & 0xff
    r |= (x[1] & 0xff) << 8
    r |= (x[2] & 0xff) << 16
    return r

def cbd(buf, paramsK):
    r = [ 0 for x in range(0, KYBER_POLY_BYTES)]
    if(paramsK == 2):
        for i in range(0, KYBER_N // 4):
            t = convert_byte_to_24_bit_unsigned_int(buf[3 * i:])
            d = t & 0x00249249
            d = d + ((t >> 1) & 0x00249249)
            d = d + ((t >> 2) & 0x00249249)
            for j in range(0,4):
                a = ((d >> (6 * j + 0)) & 0x7)
                b = ((d >> (6 * j + KYBER_ETAK512)) & 0x7)
                r[4 * i + j] = (a - b)
    else:
        for i in range(0, KYBER_N // 8):
            t = convert_byte_to_32_bit_unsigned_int(buf[4 * i:])
            d = t & 0x55555555
            d = d + ((t >> 1) & 0x55555555)
            for j in range(0,8):
                a = ((d >> (4 * j + 0)) & 0x3)
                b = ((d >> (4 * j + KYBER_ETAK768_1024)) & 0x3)
                r[8 * i + j] = (a - b)
    return r

def montgomery_reduce(a):
    """
    :param a: big integer (i.e. long)
    :return: a reduced (16 bit signed short)
    """
    u = cast_to_short(a * KYBER_Q_INV)
    t = (u * KYBER_Q)
    if u >= 2**31:
        u -= 2**32
    t = a - t
    t >>= 16
    return t

def barrett_reduce(a):
    """
    :param a: big integer (i.e. long)
    :return: a reduced (16 signed short)
    """
    shift = 1 << 26
    v = cast_to_short((shift + (KYBER_Q // 2)) // KYBER_Q)
    t = cast_to_short((v * a) >> 26)
    t = cast_to_short(t * KYBER_Q)
    res = cast_to_short(a - t)
    return res


def conditional_subq(a):
    """
    conditionally subtract Q (from KyberParams) from a
    :param a: short value
    :return: short value
    """
    a = cast_to_short(a - KYBER_Q)
    a = cast_to_short(a + cast_to_int32(cast_to_int32(a >> 15) & KYBER_Q))
    return a
