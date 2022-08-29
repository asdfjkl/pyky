from Crypto.Random import get_random_bytes
from cpake import generate_kyber_keys, encrypt, decrypt
from params import KYBER_512SK_BYTES, KYBER_SYM_BYTES, KYBER_SS_BYTES, KYBER_INDCPA_SECRETKEY_BYTES_K512, \
    KYBER_INDCPA_PUBLICKEYBYTES_K512
from Crypto.Hash import SHA3_256, SHA3_512, SHAKE256
from util import cast_to_byte, compare_const, cast_to_int32

def verify_seed(variant):
    if(len(variant) > KYBER_SYM_BYTES):
        raise ValueError("verify seed failed")
    elif(len(variant) < KYBER_SYM_BYTES):
        temp_data = [ 0 for x in range(0, KYBER_SYM_BYTES)]
        for i in range(0, len(variant)):
            temp_data[i] = variant[i]
        empty_bytes = [0 for x in range(0, KYBER_SYM_BYTES - len(variant))]
        for i in range(0, len(empty_bytes)):
            temp_data[i + len(variant)] = empty_bytes[i]
        return temp_data
    else:
        return variant

def kem_keygen512():
    """
    generate kyber keys for security level 512
    :return: tuple of (private_key, public key), each a byte array
    """
    params_k = 2
    packed_privkey, packed_pubkey = generate_kyber_keys(params_k)
    private_key_fixed_length = [ 0 for x in range(0,KYBER_512SK_BYTES)]
    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in packed_pubkey]))
    encoded_hash = md.digest()
    encoded_hash = [ cast_to_byte(x) for x in encoded_hash ]
    pkh = [0 for x in range(0, len(encoded_hash))]
    for i in range(0, len(encoded_hash)):
        pkh[i] = encoded_hash[i]
    rnd = get_random_bytes(KYBER_SYM_BYTES)
    rnd = bytearray([x & 0xFF for x in rnd])
    offset_end = len(packed_privkey)
    for i in range(0, offset_end):
        private_key_fixed_length[i] = packed_privkey[i]
    for i in range(0, len(packed_pubkey)):
        private_key_fixed_length[i+offset_end] = packed_pubkey[i]
    offset_end += len(packed_pubkey)
    for i in range(0, len(pkh)):
        private_key_fixed_length[i+offset_end] = pkh[i]
    offset_end += len(pkh)
    for i in range(0, len(rnd)):
        private_key_fixed_length[i+offset_end] = rnd[i]
    return (private_key_fixed_length, packed_pubkey)

def kem_encaps512(pubkey, seed=None):
    """

    :param seed:
    :param pubkey:
    :return: (cipher, shared_secret)
    """
    if(seed != None and (len(seed) != KYBER_SYM_BYTES)):
            raise ValueError("KEM encaps: Seed has incorrect length!")

    if(seed == None):
        seed = get_random_bytes(KYBER_SYM_BYTES)

    seed = bytearray([x & 0xFF for x in seed])

    params_k = 2

    md = SHA3_256.new()
    md.update(bytearray(seed))
    Hm = md.digest()
    Hm = [ cast_to_byte(x) for x in Hm ]

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in pubkey]))
    Hpk = md.digest()
    Hpk = [ cast_to_byte(x) for x in Hpk ]

    m = Hm + Hpk

    md512 = SHA3_512.new()
    md512.update(bytearray([x & 0xFF for x in m]))
    kr = md512.digest()
    kr = [ cast_to_byte(x) for x in kr]
    K = kr[0:KYBER_SYM_BYTES]
    r = [ kr[i + KYBER_SYM_BYTES] for i in range(0, len(kr) - KYBER_SYM_BYTES)]
    c = encrypt(Hm, pubkey, r, params_k)

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in c]))
    Hc = md.digest()
    Hc = [ cast_to_byte(x) for x in Hc ]
    KHc = K + Hc

    xof = SHAKE256.new()
    xof.update(bytearray([ x & 0xFF for x in KHc]))
    shared_secret = xof.read(KYBER_SYM_BYTES)
    shared_secret = [ cast_to_byte(x) for x in shared_secret]
    return shared_secret, c

def kem_decaps512(private_key, ciphertext):
    """

    :param private_key:
    :param ciphertext:
    :return: (shared_secret, variant)
    """
    params_k = 2
    sk = private_key[0: KYBER_INDCPA_SECRETKEY_BYTES_K512]
    pk = private_key[KYBER_INDCPA_SECRETKEY_BYTES_K512:KYBER_INDCPA_SECRETKEY_BYTES_K512+KYBER_INDCPA_PUBLICKEYBYTES_K512]
    z = private_key[KYBER_512SK_BYTES - KYBER_SYM_BYTES:]
    h = private_key[KYBER_512SK_BYTES - 2 * KYBER_SYM_BYTES:KYBER_512SK_BYTES - KYBER_SYM_BYTES]
    m_ = decrypt(ciphertext, sk, params_k)

    md512 = SHA3_512.new()
    md512.update(bytearray([ x & 0xFF for x in (m_[:] + h[:])]))
    K_r_ = md512.digest()
    K_r_ = [ cast_to_byte(x) for x in K_r_ ]
    r_ = K_r_[-KYBER_SYM_BYTES:]
    cmp = encrypt(m_, pk, r_, params_k)
    md = SHA3_256.new()
    md.update(bytearray([x & 0xff for x in ciphertext]))
    Hc = md.digest()
    Hc = [ cast_to_byte(x) for x in Hc ]
    k = K_r_[0:KYBER_SYM_BYTES]
    if(cmp == ciphertext):
        temp_buf = k + Hc
    else:
        temp_buf = z[:] + Hc
    xof = SHAKE256.new()
    xof.update(bytearray([ x & 0xFF for x in temp_buf]))
    sharedSecretFixedLength = xof.read(KYBER_SS_BYTES)
    # could also return buf for debugging...
    return [cast_to_byte(x) for x in sharedSecretFixedLength ]

