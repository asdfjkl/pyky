from Crypto.Random import get_random_bytes
from cpake import generate_kyber_keys, encrypt, decrypt
from params import KYBER_512SK_BYTES, KYBER_768SK_BYTES, KYBER_1024SK_BYTES, KYBER_SYM_BYTES, KYBER_SS_BYTES, \
    KYBER_INDCPA_SECRETKEY_BYTES_K512, KYBER_INDCPA_PUBLICKEYBYTES_K512, \
    KYBER_INDCPA_SECRETKEY_BYTES_K768, KYBER_INDCPA_PUBLICKEYBYTES_K768, \
    KYBER_INDCPA_SECRETKEY_BYTES_K1024, KYBER_INDCPA_PUBLICKEYBYTES_K1024
from Crypto.Hash import SHA3_256, SHA3_512, SHAKE256
from util import cast_to_byte

def kem_keygen512():
    """
    generate kyber keys for security level 512
    :return: tuple of (private_key, public key), each a byte array
    """
    params_k = 2
    sk_, pk = generate_kyber_keys(params_k)

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in pk]))
    H_pk = md.digest()
    H_pk = [ cast_to_byte(x) for x in H_pk ]
    pkh = [0 for x in range(0, len(H_pk))]
    for i in range(0, len(H_pk)):
        pkh[i] = H_pk[i]
    z = get_random_bytes(KYBER_SYM_BYTES)
    z = [ cast_to_byte(x) for x in z]

    sk = sk_[:] + pk[:] + H_pk[:] + z[:]

    return (sk, pk)

def kem_keygen768():
    """
    generate kyber keys for security level 768
    :return: tuple of (private_key, public key), each a byte array
    """
    params_k = 3
    sk_, pk = generate_kyber_keys(params_k)

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in pk]))
    H_pk = md.digest()
    H_pk = [ cast_to_byte(x) for x in H_pk ]
    pkh = [0 for x in range(0, len(H_pk))]
    for i in range(0, len(H_pk)):
        pkh[i] = H_pk[i]
    z = get_random_bytes(KYBER_SYM_BYTES)
    z = [ cast_to_byte(x) for x in z]

    sk = sk_[:] + pk[:] + H_pk[:] + z[:]

    return (sk, pk)

def kem_keygen1024():
    """
    generate kyber keys for security level 1024
    :return: tuple of (private_key, public key), each a byte array
    """
    params_k = 4
    sk_, pk = generate_kyber_keys(params_k)

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in pk]))
    H_pk = md.digest()
    H_pk = [ cast_to_byte(x) for x in H_pk ]
    pkh = [0 for x in range(0, len(H_pk))]
    for i in range(0, len(H_pk)):
        pkh[i] = H_pk[i]
    z = get_random_bytes(KYBER_SYM_BYTES)
    z = [ cast_to_byte(x) for x in z]

    sk = sk_[:] + pk[:] + H_pk[:] + z[:]

    return (sk, pk)



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


def kem_encaps768(pubkey, seed=None):
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

    params_k = 3

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


def kem_encaps1024(pubkey, seed=None):
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

    params_k = 4

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


def kem_decaps768(private_key, ciphertext):
    """

    :param private_key:
    :param ciphertext:
    :return: (shared_secret, variant)
    """
    params_k = 3
    sk = private_key[0: KYBER_INDCPA_SECRETKEY_BYTES_K768]
    pk = private_key[KYBER_INDCPA_SECRETKEY_BYTES_K768:KYBER_INDCPA_SECRETKEY_BYTES_K768+KYBER_INDCPA_PUBLICKEYBYTES_K768]
    z = private_key[KYBER_768SK_BYTES - KYBER_SYM_BYTES:]
    h = private_key[KYBER_768SK_BYTES - 2 * KYBER_SYM_BYTES:KYBER_768SK_BYTES - KYBER_SYM_BYTES]
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


def kem_decaps1024(private_key, ciphertext):
    """

    :param private_key:
    :param ciphertext:
    :return: (shared_secret, variant)
    """
    params_k = 4
    sk = private_key[0: KYBER_INDCPA_SECRETKEY_BYTES_K1024]
    pk = private_key[KYBER_INDCPA_SECRETKEY_BYTES_K1024:KYBER_INDCPA_SECRETKEY_BYTES_K1024+KYBER_INDCPA_PUBLICKEYBYTES_K1024]
    z = private_key[KYBER_1024SK_BYTES - KYBER_SYM_BYTES:]
    h = private_key[KYBER_1024SK_BYTES - 2 * KYBER_SYM_BYTES:KYBER_1024SK_BYTES - KYBER_SYM_BYTES]
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
