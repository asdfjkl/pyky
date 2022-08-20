from params import KYBER_N, KYBER_Q, KYBER_POLY_COMPRESSED_BYTES_768, \
    KYBER_POLY_COMPRESSED_BYTES_1024, KYBER_POLY_BYTES, KYBER_SYM_BYTES, \
    KYBER_ETAK512, KYBER_ETAK768_1024, KYBER_POLYVEC_COMPRESSED_BYTES_K512, \
    KYBER_POLYVEC_COMPRESSED_BYTES_K768, KYBER_POLYVEC_COMPRESSED_BYTES_K1024
from util import conditional_subq, cast_to_byte, cast_to_short, cast_to_int32, cast_to_long64, \
    cbd, montgomery_reduce, barrett_reduce
from prf import generate_prf_byte_array
from ntt import ntt, inv_ntt, base_multiplier, NTT_ZETAS

def poly_conditional_subq(r):
    """
    subtract KYBER_Q from each coefficient from polynomial r
    :param r:
    :return:
    """
    for i in range(0, KYBER_N):
        r[i] = conditional_subq(r[i])
    return r

def compress_poly(poly_a, param_k):
    """
    performs lossy compression and serialization of a polynomial
    :param poly_a:
    :param param_k:
    :return:
    """
    t = [ 0 for x in range(0,8)] # bytes
    poly_a = poly_conditional_subq(poly_a)
    rr = 0 # int
    r = [] # bytes
    if(param_k == 2 or param_k == 3):
        r = [ 0 for x in range(0, KYBER_POLY_COMPRESSED_BYTES_768) ]
        for i in range(0, KYBER_N // 8):
            for j in range(0,8):
                t[j] = cast_to_byte((((((poly_a[8 * i + j]) << 4) + (KYBER_Q // 2)) // (KYBER_Q)) & 15))
            r[rr + 0] = cast_to_byte(t[0] | (t[1] << 4))
            r[rr + 1] = cast_to_byte(t[2] | (t[3] << 4))
            r[rr + 2] = cast_to_byte(t[4] | (t[5] << 4))
            r[rr + 3] = cast_to_byte(t[6] | (t[7] << 4))
            rr = rr + 4
    else:
        r = [ 0 for x in range(0, KYBER_POLY_COMPRESSED_BYTES_1024) ]
        for i in range(0, KYBER_N // 8):
            for j in range(0,8):
                t[j] = cast_to_byte((((((poly_a[8 * i + j]) << 5) + (KYBER_Q // 2)) // (KYBER_Q)) & 31))
            r[rr + 0] = cast_to_byte((t[0] >> 0) | (t[1] << 5))
            r[rr + 1] = cast_to_byte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7))
            r[rr + 2] = cast_to_byte((t[3] >> 1) | (t[4] << 4))
            r[rr + 3] = cast_to_byte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6))
            r[rr + 4] = cast_to_byte((t[6] >> 2) | (t[7] << 3))
            rr = rr + 5
    return r

def decompress_poly(a, params_k):
    r = [ 0 for x in range(0, KYBER_POLY_BYTES)] # short
    aa = 0
    if(params_k == 2 or params_k == 3):
        for i in range(0, KYBER_N // 2):
            r[2 * i + 0] = cast_to_short((((cast_to_int32 (a[aa] & 0xFF) & 15) * KYBER_Q) + 8) >> 4)
            r[2 * i + 1] = cast_to_short((((cast_to_int32 (a[aa] & 0xFF) >> 4) * KYBER_Q) + 8) >> 4)
            aa = aa + 1
    else:
        t = [ 0 for x in range(0,8)] # long64
        for i in range(0, KYBER_N // 8):
            t[0] = cast_to_long64(cast_to_int32(a[aa + 0] & 0xFF) >> 0) & 0xFF
            t[1] = cast_to_long64 (cast_to_byte ((cast_to_int32 (a[aa + 0] & 0xFF) >> 5)) | cast_to_byte (cast_to_int32 (a[aa + 1] & 0xFF) << 3)) & 0xFF
            t[2] = cast_to_long64 (cast_to_int32(a[aa + 1] & 0xFF) >> 2) & 0xFF
            t[3] = cast_to_long64 (cast_to_byte ((cast_to_int32 (a[aa + 1] & 0xFF) >> 7)) | cast_to_byte (cast_to_int32 (a[aa + 2] & 0xFF) << 1)) & 0xFF
            t[4] = cast_to_long64 (cast_to_byte ((cast_to_int32 (a[aa + 2] & 0xFF) >> 4)) | cast_to_byte (cast_to_int32 (a[aa + 3] & 0xFF) << 4)) & 0xFF
            t[5] = cast_to_long64 (cast_to_int32 (a[aa + 3] & 0xFF) >> 1) & 0xFF
            t[6] = cast_to_long64 (cast_to_byte ((cast_to_int32 (a[aa + 3] & 0xFF) >> 6)) | cast_to_byte (cast_to_int32 (a[aa + 4] & 0xFF) << 2)) & 0xFF
            t[7] = (cast_to_long64 (cast_to_int32 (a[aa + 4] & 0xFF) >> 3)) & 0xFF
            aa = aa + 5
            for j in range(0,8):
                r[8 * i + j] = cast_to_short (((cast_to_long64 (t[j] & 31) * (KYBER_Q)) + 16) >> 5)
    return r

def poly_to_bytes(a):
    """
    serialize a polynomial in to an array of bytes
    :param a:
    :return:
    """
    t0 = 0
    t1 = 0
    r = [0 for x in range(0, KYBER_POLY_BYTES)]
    a = poly_conditional_subq(a)
    for i in range(0, KYBER_N // 2):
        t0 = (cast_to_int32 (a[2 * i] & 0xFFFF))
        t1 = (cast_to_int32 (a[2 * i + 1]) & 0xFFFF)
        r[3 * i + 0] = cast_to_byte (t0 >> 0)
        r[3 * i + 1] = cast_to_byte (cast_to_int32 (t0 >> 8) | cast_to_int32 (t1 << 4))
        r[3 * i + 2] = cast_to_byte (t1 >> 4)
    return r

def poly_from_bytes(a):
    """
     de-serialize a byte array into a polynomial
    :param a:
    :return:
    """
    r = [ 0 for x in range(0, KYBER_POLY_BYTES)]
    for i in range(0, KYBER_N // 2):
        r[2 * i] = cast_to_short((((a[3 * i + 0] & 0xFF) >> 0) | ((a[3 * i + 1] & 0xFF) << 8)) & 0xFFF)
        r[2 * i + 1] = cast_to_short((((a[3 * i + 1] & 0xFF) >> 4) | ((a[3 * i + 2] & 0xFF) << 4)) & 0xFFF)
    return r

def poly_from_data(msg):
    """
    convert a 32-byte message to a polynomial
    :param msg: byte array
    :return: short array
    """
    r = [ 0 for x in range(0, KYBER_N)]
    mask = 0
    for i in range(0, KYBER_N // 8):
        for j in range(0,8):
            mask = cast_to_short (-1 * cast_to_short (((msg[i] & 0xFF) >> j) & 1))
            r[8 * i + j] = cast_to_short (mask & cast_to_short ((KYBER_Q + 1) // 2))
    return r

def poly_to_msg(a):
    """
    convert a polynomial to a 32 bit message
    :param a: short array
    :return: byte array
    """
    msg = [ 0 for x in range(0, KYBER_SYM_BYTES)]
    a = poly_conditional_subq(a)
    for i in range(0, KYBER_N // 8):
        for j in range(0,8):
            t = cast_to_int32(((((cast_to_int32 (a[8 * i + j])) << 1) + (KYBER_Q // 2)) // KYBER_Q) & 1)
            msg[i] = cast_to_byte(msg[i] | (t << j))
    return msg

def get_noise_poly(seed, nonce, params_k):
    """
    generate a deterministic noise polynomial from a seed and nonce
    :param seed: byte array
    :param nonce: byte
    :param params_k: int
    :return: short array (poly)
    """
    l = None
    if(params_k == 2):
        l = KYBER_ETAK512 * KYBER_N // 4
    else:
        l = KYBER_ETAK768_1024 * KYBER_N // 4
    p = generate_prf_byte_array(l, seed, nonce)
    return cbd(p, params_k)

def poly_ntt(r):
    """
    computes an in-place negacyclic number-theoretic transform (NTT) of a polynomial
    :param r: array of shorts, assumed in normal order
    :return: array of shots,  bit-reversed order
    """
    return ntt(r)

def poly_inv_ntt_mont(r):
    """
    computes an in-place inverse of a negacyclic number-theoretic transform (NTT) of a polynomial
    :param r: array of shorts, assumes bit-reversed order
    :return: array of shorts, normal order
    """
    return inv_ntt(r)


def poly_basemul_mont(poly_a, poly_b):
    """
    multiply two polynomials in the number-theoretic transform (NTT) domain
    :param poly_a: array of shorts
    :param poly_b: array of shorts
    :return: array of shorts
    """
    for i in range(0, KYBER_N // 4):
        rx = base_multiplier(poly_a[4*i+0], poly_a[4*i+1],
                             poly_b[4*i+0], poly_b[4*i+1],
                             cast_to_short(NTT_ZETAS[64 + i]))
        ry = base_multiplier(poly_a[4*i+2], poly_a[4*i+3],
                             poly_b[4*i+2], poly_b[4*i+3],
                             cast_to_short(-1 * NTT_ZETAS[64 + i]))
        poly_a[4 * i + 0] = rx[0]
        poly_a[4 * i + 1] = rx[1]
        poly_a[4 * i + 2] = ry[0]
        poly_a[4 * i + 3] = ry[1]
    return poly_a

def poly_to_mont(poly_r):
    """
    performs an in-place conversion of all coefficients of a polynomial from
    the normal domain to the Montgomery domain
    :param poly_r: short array
    :return: short array
    """
    for i in range(0, KYBER_N):
        poly_r[i] = montgomery_reduce(cast_to_long64(poly_r[i]*1353))
    return poly_r

def poly_reduce(r):
    """
    apply Barrett reduction to all coefficients of this polynomial
    :param r: array of shorts
    :return: array of shorts
    """
    for i in range(0, KYBER_N):
        r[i] = barrett_reduce(r[i])
    return r

def poly_conditional_subq(r):
    """
    apply the conditional subtraction of Q (KyberParams) to each coefficient of a polynomial
    :param r: short array
    :return: short array
    """
    for i in range(0, KYBER_N):
        r[i] = conditional_subq(r[i])
    return r

def poly_add(poly_a, poly_b):
    """
    add two polynomials
    :param poly_a: short array
    :param poly_b: short array
    :return: short array
    """
    for i in range(0, KYBER_N):
        poly_a[i] = cast_to_short(poly_a[i] + poly_b[i])
    return poly_a

def poly_sub(poly_a, poly_b):
    """
    subtract poly_b from poly_a
    :param poly_a: short array
    :param poly_b: short array
    :return: short array
    """
    for i in range(0, KYBER_N):
        poly_a[i] = cast_to_short(poly_a[i] - poly_b[i])
    return poly_a

def generate_new_polyvec(params_k):
    return [[ 0 for x in range(0, KYBER_POLY_BYTES) ] for y in range(0, params_k)]

def polyvec_csubq(r, params_k):
    """
    applies the conditional subtraction of Q (KyberParams) to each coefficient of
    each element of a vector of polynomials.
    :param r:
    :param params_k:
    :return:
    """
    for i in range(0, params_k):
        r[i] = poly_conditional_subq(r[i])
    return r

def compress_polyvec(a, params_k):
    """
    serialize vector of polynomials
    :param a: short array of dims [params_k][poly_len]
    :param params_k: int
    :return: byte array
    """
    a = polyvec_csubq(a, params_k) #? required?
    rr = 0 # int
    r = [] # byte array
    t = [] #long
    if(params_k == 2):
        r = [ 0 for x in range(0, KYBER_POLYVEC_COMPRESSED_BYTES_K512)]
    elif(params_k == 3):
        r = [ 0 for x in range(0, KYBER_POLYVEC_COMPRESSED_BYTES_K768)]
    else:
        r = [ 0 for x in range(0, KYBER_POLYVEC_COMPRESSED_BYTES_K1024)]
    if(params_k == 2 or params_k == 3):
        t = [ 0 for x in range(0,4)]
        for i in range(0, params_k):
            for j in range(0, KYBER_N // 4):
                for k in range(0, 4):
                    t[k] = (cast_to_long64 ((cast_to_long64 (cast_to_long64 (a[i][4 * j + k]) << 10) +
                                             cast_to_long64 (KYBER_Q // 2)) // cast_to_long64 (KYBER_Q)) & 0x3ff)
                r[rr + 0] = cast_to_byte (t[0] >> 0)
                r[rr + 1] = cast_to_byte ((t[0] >> 8) | (t[1] << 2))
                r[rr + 2] = cast_to_byte ((t[1] >> 6) | (t[2] << 4))
                r[rr + 3] = cast_to_byte ((t[2] >> 4) | (t[3] << 6))
                r[rr + 4] = cast_to_byte ((t[3] >> 2))
                rr = rr + 5
    else:
        t = [ 0 for x in range(0,8)]
        for i in range(0, params_k):
            for j in range(0, KYBER_N // 8):
                for k in range(0, 8):
                    t[k] = (cast_to_long64 ((cast_to_long64 (cast_to_long64 (a[i][8 * j + k]) << 11) +
                                             cast_to_long64 (KYBER_Q // 2)) // cast_to_long64 (KYBER_Q)) & 0x7ff)
                r[rr + 0] = cast_to_byte ((t[0] >> 0))
                r[rr + 1] = cast_to_byte ((t[0] >> 8) | (t[1] << 3))
                r[rr + 2] = cast_to_byte ((t[1] >> 5) | (t[2] << 6))
                r[rr + 3] = cast_to_byte ((t[2] >> 2))
                r[rr + 4] = cast_to_byte ((t[2] >> 10) | (t[3] << 1))
                r[rr + 5] = cast_to_byte ((t[3] >> 7) | (t[4] << 4))
                r[rr + 6] = cast_to_byte ((t[4] >> 4) | (t[5] << 7))
                r[rr + 7] = cast_to_byte ((t[5] >> 1))
                r[rr + 8] = cast_to_byte ((t[5] >> 9) | (t[6] << 2))
                r[rr + 9] = cast_to_byte ((t[6] >> 6) | (t[7] << 5))
                r[rr + 10] = cast_to_byte ((t[7] >> 3))
                rr = rr + 11
    return r

def decompress_polyvec(a, params_k):
    """
    de-serialize and decompress a vector of polynomials (lossy!)
    :param a:
    :param params_k:
    :return:
    """
    r = [[ 0 for x in range(0, KYBER_POLY_BYTES)] for y in range(0, params_k) ] # short array
    aa = 0 # int
    t = [] # int array
    if(params_k == 2 or params_k == 3):
        t = [0 for x in range(0,4)]
        for i in range(0, params_k):
            for j in range(0, KYBER_N // 4):
                t[0] = ((a[aa + 0] & 0xFF) >> 0) | ((a[aa + 1] & 0xFF) << 8)
                t[1] = ((a[aa + 1] & 0xFF) >> 2) | ((a[aa + 2] & 0xFF) << 6)
                t[2] = ((a[aa + 2] & 0xFF) >> 4) | ((a[aa + 3] & 0xFF) << 4)
                t[3] = ((a[aa + 3] & 0xFF) >> 6) | ((a[aa + 4] & 0xFF) << 2)
                aa = aa + 5
                for k in range(0,4):
                    r[i][4 * j + k] = cast_to_short ((cast_to_long64 (t[k] & 0x3FF) * cast_to_long64 (KYBER_Q) + 512) >> 10)
    else:
        t = [0 for x in range(0,8)]
        for i in range(0, params_k):
            for j in range(0, KYBER_N // 8):
                t[0] = (((a[aa + 0] & 0xff) >> 0) | ((a[aa + 1] & 0xff) << 8))
                t[1] = (((a[aa + 1] & 0xff) >> 3) | ((a[aa + 2] & 0xff) << 5))
                t[2] = (((a[aa + 2] & 0xff) >> 6) | ((a[aa + 3] & 0xff) << 2) | ((a[aa + 4] & 0xff) << 10))
                t[3] = (((a[aa + 4] & 0xff) >> 1) | ((a[aa + 5] & 0xff) << 7))
                t[4] = (((a[aa + 5] & 0xff) >> 4) | ((a[aa + 6] & 0xff) << 4))
                t[5] = (((a[aa + 6] & 0xff) >> 7) | ((a[aa + 7] & 0xff) << 1) | ((a[aa + 8] & 0xff) << 9))
                t[6] = (((a[aa + 8] & 0xff) >> 2) | ((a[aa + 9] & 0xff) << 6))
                t[7] = (((a[aa + 9] & 0xff) >> 5) | ((a[aa + 10] & 0xff) << 3))
                aa = aa + 11
                for k in range(0,8):
                    r[i][8 * j + k] = cast_to_short ((cast_to_long64 (t[k] & 0x7FF) * cast_to_long64 (KYBER_Q) + 1024) >> 11)
    return r

def polyvec_to_bytes(poly_a, params_k):
    """
    serialize a polynomial vector to a byte array
    :param poly_a: short array
    :param params_k: int
    :return: byte array (as ints, but each int is in -127 ... 128)
    """
    r = [ 0 for x in range(0, params_k * KYBER_POLY_BYTES)]
    for i in range(0, params_k):
        byte_a = poly_to_bytes(poly_a[i])
        for j in range(0, len(byte_a)):
            r[(i*KYBER_POLY_BYTES)+j] = byte_a[j]
    return r

def polyvec_from_bytes(poly_a, params_k):
    """
    deserialize a byte array into a polynomial vector
    :param poly_a: array of shorts (polyvec)
    :param params_k: int
    :return: short double array
    """
    r = [[ 0 for x in range(0, KYBER_POLY_BYTES)] for y in range(0, params_k)]
    for i in range(0, params_k):
        start = i * KYBER_POLY_BYTES
        end = (i+1) * KYBER_POLY_BYTES
        tmp_i = []
        for j in range(start, end):
            tmp_i.append(poly_a[j])
        r[i] = poly_from_bytes(tmp_i)
    return r

def polyvec_ntt(r, params_k):
    """
    applies forward number-theoretic transforms (NTT) to all elements of a
    vector of polynomials
    :param r: double array of shorts
    :param params_k: int
    :return: double array of shorts
    """
    for i in range(0, params_k):
        r[i] = poly_ntt(r[i])
    return r

def polyvec_inv_ntt(r, params_k):
    """
    applies the inverse number-theoretic transform (NTT) to all elements of a
    vector of polynomials and multiplies by montgomery factor 2**16
    :param r: double array of shorts
    :param params_k: int
    :return: double array of shorts
    """
    for i in range(0, params_k):
        r[i] = poly_inv_ntt_mont(r[i])
    return r

def polyvec_pointwise_acc_mont(poly_a, poly_b, params_k):
    """
    pointwise-multiplies elements of the given polynomial-vectors,
    accumulates the results, and then multiplies by 2**-16
    :param poly_a: double array of shorts
    :param poly_b: double array of shorts
    :param params_k: int
    :return: array of shorts
    """
    r = poly_basemul_mont(poly_a[0], poly_b[0])
    for i in range(1, params_k):
        t = poly_basemul_mont(poly_a[i], poly_b[i])
        r = poly_add(r, t)
    return poly_reduce(r)

def polyvec_reduce(r, params_k):
    """
    applies barrett reduction to each coefficient of each element of a vector of polynomials
    :param r: double array of shorts (polyvec)
    :param params_k: int
    :return: double array of shorts (polyvec)
    """
    for i in range(0, params_k):
        r[i] = poly_reduce(r[i])
    return r

def polyvec_csubq(r, params_k):
    """
    applies condictional subtraction of Q (Kyber Parameter) to each
    coefficient of each element of a vector of polynomials
    :param r: double array of shorts (polyvec)
    :param params_k: int
    :return: double array of shorts (polyvec)
    """
    for i in range(0, params_k):
        r[i] = poly_conditional_subq(r[i])
    return r

def polyvec_add(poly_a, poly_b, params_k):
    """
    add two polynomial vectors
    :param poly_a: double array of shorts
    :param poly_b: double array of shorts
    :param params_k: int
    :return: double array of shorts
    """
    for i in range(0, params_k):
        poly_a[i] = poly_add(poly_a[i], poly_b[i])
    return poly_a
