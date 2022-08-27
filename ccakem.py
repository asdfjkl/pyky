from Crypto.Random import get_random_bytes
from cpake import generate_kyber_keys, encrypt, decrypt
from params import KYBER_512SK_BYTES, KYBER_SYM_BYTES, KYBER_SS_BYTES, KYBER_INDCPA_SECRETKEY_BYTES_K512, \
    KYBER_INDCPA_PUBLICKEYBYTES_K512
from Crypto.Hash import SHA3_256, SHA3_512, SHAKE256
from util import cast_to_byte, compare_const, cast_to_int32

def verify_variant(variant):
    if(len(variant) > KYBER_SYM_BYTES):
        raise ValueError("verify variant failed")
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

def kem_encrypt512(variant, pubkey):
    """

    :param variant:
    :param pubkey:
    :return: (cipher, shared_secret)
    """
    variant = verify_variant(variant)
    params_k = 2

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in variant]))
    buf1 = md.digest()
    buf1 = [ cast_to_byte(x) for x in buf1 ]

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in pubkey]))
    buf2 = md.digest()
    buf2 = [ cast_to_byte(x) for x in buf2 ]

    buf3 = buf1 + buf2

    md512 = SHA3_512.new()
    md512.update(bytearray([x & 0xFF for x in buf3]))
    kr = md512.digest()
    kr = [ cast_to_byte(x) for x in kr]
    sub_kr = [ kr[i + KYBER_SYM_BYTES] for i in range(0, len(kr) - KYBER_SYM_BYTES)]
    ciphertext = encrypt(buf1, pubkey, sub_kr, params_k)

    md = SHA3_256.new()
    md.update(bytearray([x & 0xFF for x in ciphertext]))
    krc = md.digest()
    krc = [ cast_to_byte(x) for x in krc ]
    new_kr = [ 0 for x in range(0, KYBER_SYM_BYTES + len(krc))]
    for i in range(0, KYBER_SYM_BYTES):
        new_kr[i] = kr[i]
    for i in range(0, len(krc)):
        new_kr[i+KYBER_SYM_BYTES] = krc[i]
    xof = SHAKE256.new()
    xof.update(bytearray([ x & 0xFF for x in new_kr]))
    shared_secret = xof.read(KYBER_SYM_BYTES)
    shared_secret = [ cast_to_byte(x) for x in shared_secret]
    return shared_secret, ciphertext

def kem_decrypt512(private_key, ciphertext):
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


"""
    /**
     * Get the shared secret with the given cipher text and private key
     *
     * @param kyberCiphertext
     * @return
     */
    private KyberDecrypted decrypt512(KyberCipherText kyberCiphertext) {


        byte[] cmp = Indcpa.encrypt(buf, publicKey, subKr, paramsK);
        byte fail = (byte) KyberKeyUtil.constantTimeCompare(ciphertext, cmp);
        if (fail == (byte) 0) {
            for (int i = 0; i < KyberParams.paramsSymBytes; i++) {
                int length = KyberParams.Kyber512SKBytes - KyberParams.paramsSymBytes + i;
                byte[] skx = new byte[length];
                System.arraycopy(privateKey, 0, skx, 0, length);
                kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (skx[i] & 0xFF))));
            }
            byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
            System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
            System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
            KeccakSponge xof = new Shake256();
            xof.getAbsorbStream().write(tempBuf);
            xof.getSqueezeStream().read(sharedSecretFixedLength);

            return new KyberDecrypted(new KyberSecretKey(sharedSecretFixedLength, null, null), new KyberVariant(buf));
        } else {
            throw new IllegalArgumentException("Invalid CipherText for this Private Key!");
        }
    }
"""