from poly import polyvec_to_bytes, polyvec_from_bytes, compress_poly, compress_polyvec, decompress_polyvec, decompress_poly, \
    generate_new_polyvec
from params import KYBER_INDCPA_PUBLICKEYBYTES_K512, KYBER_INDCPA_PUBLICKEYBYTES_K768, KYBER_INDCPA_PUBLICKEYBYTES_K1024, \
    KYBER_POlYVEC_BYTES_512, KYBER_POlYVEC_BYTES_768, KYBER_POlYVEC_BYTES_1024, KYBER_POLYVEC_COMPRESSED_BYTES_K512, \
    KYBER_POLYVEC_COMPRESSED_BYTES_K768, KYBER_POLYVEC_COMPRESSED_BYTES_K1024, KYBER_POLY_BYTES, KYBER_Q, KYBER_N
from util import cast_to_int32, cast_to_short, cast_to_byte
from Crypto.Hash import SHAKE128, SHAKE256


def pack_public_key(public_key, seed, params_k):
    """
    pack the public key together with the seed into a polynomial
    :param public_key: double array of shorts (polyvec)
    :param seed: array of bytes
    :param params_k: int
    :return: array of bytes
    """
    initial_array = polyvec_to_bytes(public_key, params_k)
    packed_public_key = []
    if(params_k == 2):
        packed_public_key = [ 0 for x in range(0,KYBER_INDCPA_PUBLICKEYBYTES_K512)]
        for i in range(0, len(initial_array)):
            packed_public_key[i] = initial_array[i]
        for i in range(len(initial_array), len(initial_array) + len(seed)):
            packed_public_key[i] = seed[i - len(initial_array)]
    elif(params_k == 3):
        packed_public_key = [ 0 for x in range(0,KYBER_INDCPA_PUBLICKEYBYTES_K768)]
        for i in range(0, len(initial_array)):
            packed_public_key[i] = initial_array[i]
        for i in range(len(initial_array), len(initial_array) + len(seed)):
            packed_public_key[i] = seed[i - len(initial_array)]
    else: # k == 3
        packed_public_key = [ 0 for x in range(0,KYBER_INDCPA_PUBLICKEYBYTES_K1024)]
        for i in range(0, len(initial_array)):
            packed_public_key[i] = initial_array[i]
        for i in range(len(initial_array), len(initial_array) + len(seed)):
            packed_public_key[i] = seed[i - len(initial_array)]
    return packed_public_key

def unpack_public_key(packed_public_key, params_k):
    """
    unpack the packed public key into the pubkey polyvec and seed
    :param packed_public_key: byte array
    :param params_k: int
    :return: (polyvec : double short array, seed : byte array (as ints))
    """
    if(params_k == 2):
        pubkey_part = [ packed_public_key[i] for i in range(0, KYBER_POlYVEC_BYTES_512)]
        pubkey = polyvec_from_bytes(pubkey_part, params_k)
        seed = [ packed_public_key[i] for i in range(KYBER_POlYVEC_BYTES_512, len(packed_public_key))]
        return (pubkey, seed)
    if(params_k == 3):
        pubkey_part = [ packed_public_key[i] for i in range(0, KYBER_POlYVEC_BYTES_768)]
        pubkey = polyvec_from_bytes(pubkey_part, params_k)
        seed = [ packed_public_key[i] for i in range(KYBER_POlYVEC_BYTES_768, len(packed_public_key))]
        return (pubkey, seed)
    else:
        pubkey_part = [ packed_public_key[i] for i in range(0, KYBER_POlYVEC_BYTES_1024)]
        pubkey = polyvec_from_bytes(pubkey_part, params_k)
        seed = [ packed_public_key[i] for i in range(KYBER_POlYVEC_BYTES_1024, len(packed_public_key))]
        return (pubkey, seed)

def pack_private_key(private_key, params_k):
    """
    pack private key into byte array
    :param private_key: 2dim array of shorts
    :param params_k: int
    :return: array of bytes (int vals)
    """
    packed_privkey = polyvec_to_bytes(private_key, params_k)
    return packed_privkey

def unpack_private_key(packed_privkey, params_k):
    """
    unpack private key from byte array into polyvec
    :param packed_privkey: array of bytes (ints)
    :param params_k: int
    :return: 2dim array of shorts (polyvec)
    """
    unpacked_private_key = polyvec_from_bytes(packed_privkey, params_k)
    return unpacked_private_key

def pack_ciphertext(b, v, params_k):
    """
    pack ciphertext into a byte array
    :param b: polyvec
    :param v: poly
    :param params_k: int
    :return: byte array
    """
    b_compress = compress_polyvec(b, params_k)
    v_compress = compress_poly(v, params_k)
    return b_compress + v_compress

def unpack_ciphertext(c, params_k):
    """
    unpack ciphertext from byte array into a polynomial vector + another vector
    :param c:
    :param params_k:
    :return: tuple of (short[][], short[]), i.e. (polyvec, vec)
    """
    bpc = None
    if params_k == 2:
        bpc = [ c[i] for i in range(0, KYBER_POLYVEC_COMPRESSED_BYTES_K512)]
    elif params_k == 3:
        bpc = [ c[i] for i in range(0, KYBER_POLYVEC_COMPRESSED_BYTES_K768)]
    else:
        bpc = [ c[i] for i in range(0, KYBER_POLYVEC_COMPRESSED_BYTES_K1024)]
    vc = [ c[i] for i in range(len(bpc), len(c)) ]
    bp_uncomp = decompress_polyvec(bpc, params_k)
    v_uncomp = decompress_poly(vc, params_k)
    return (bp_uncomp, v_uncomp)

def generate_uniform(buf, bufl, l):
    """
    runs rejection sampling on uniform random bytes to generate uniform random integers modulo `Q`
    :param uniform_random:
    :param buf:
    :param bufl:
    :param l:
    :return: tuple of (uniform_r, uniform_i), i.e. (array of shorts, int)
    """
    uniform_r = [ 0 for x in range(0, KYBER_POLY_BYTES) ]
    d1 = None
    d2 = None
    uniform_i = 0
    j = 0
    while ((uniform_i < l) and ((j+3) <= bufl)):
        d1 = cast_to_int32 ((((cast_to_int32 (buf[j] & 0xFF)) >> 0) | ((cast_to_int32 (buf[j + 1] & 0xFF)) << 8)) & 0xFFF)
        d2 = cast_to_int32 ((((cast_to_int32 (buf[j + 1] & 0xFF)) >> 4) | ((cast_to_int32 (buf[j + 2] & 0xFF)) << 4)) & 0xFFF)
        j = j + 3
        if (d1 < cast_to_int32(KYBER_Q)):
            uniform_r[uniform_i] = cast_to_short(d1)
            uniform_i += 1
        if ((uniform_i < l) and (d2 < cast_to_int32(KYBER_Q))):
            uniform_r[uniform_i] = cast_to_short(d2)
            uniform_i += 1
    return (uniform_r, uniform_i)

def generate_matrix(seed, transposed, params_k):
    """
    generate a polyvec matrix from given seed
    :param seed: byte array
    :param transposed: boolean
    :param params_k: int
    :return: 3dim short
    """
    r = [[[ 0 for x in range(0, KYBER_POLY_BYTES)] for y in range(0, params_k)] for z in range(0, params_k)]
    for i in range(0, params_k):
        r[i] = generate_new_polyvec(params_k)
        for j in range(0, params_k):
            xof = SHAKE128.new()
            seed_unsigned = [ x & 0xff for x in seed]
            xof.update(bytearray(seed_unsigned))
            ij = [0, 0]
            if (transposed):
                ij[0] = cast_to_byte(i)
                ij[1] = cast_to_byte(j)
            else:
                ij[0] = cast_to_byte(j)
                ij[1] = cast_to_byte(i)
            xof.update(bytearray(ij))
            buf = xof.read(672)
            buf_signed = [ cast_to_byte(x) for x in buf ]
            uniform_r, uniform_i = generate_uniform(buf_signed[0:504], 504, KYBER_N)
            r[i][j] = uniform_r
            while uniform_i < KYBER_N:
                missing, ctrn = generate_uniform(buf_signed[504:672], 168, KYBER_N - uniform_i)
                for k in range(uniform_i, KYBER_N):
                    r[i][j][k] = missing[k - uniform_i]
                uniform_i = uniform_i + ctrn
    return r

def generate_prf_byte_array(l, key, nonce):
    """
    pseudo-random function to derive a deterministic array of
    random bytes from the supplied secret key object and other parameters
    :param l: int
    :param key: byte array
    :param nonce: byte
    :return: byte array
    """
    hash = [ 0 for x in range(0, l)]
    xof = SHAKE256.new()
    new_key = [ key[i] for i in range(len(key))]
    new_key.append(nonce)
    new_key_unsigned = [ x & 0xff for x in new_key]
    xof.update(bytearray(new_key_unsigned))
    hash = xof.read(l)
    hash_signed = [ cast_to_byte(x) for x in hash ]
    return hash_signed
