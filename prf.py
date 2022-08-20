from Crypto.Hash import SHAKE256
from util import cast_to_byte

def generate_prf_byte_array(l, key, nonce):
    """
    pseudo-random function to derive a deterministic array of random bytes
    from the supplied secret key and a nonce
    :param l: int (size of random byte array)
    :param key: byte array
    :param nonce: byte
    :return: random byte array (hash)
    """
    hash = [ 0 for x in range(l)]
    xof = SHAKE256.new()
    new_key = [ 0 for x in range(0, len(key) + 1)]
    for i in range(0, len(key)):
        new_key[i] = key[i]
    new_key[len(key)] = nonce
    new_key = [ x & 0xff for x in new_key]
    xof.update(bytearray(new_key))
    hash = xof.read(l)
    hash = [ cast_to_byte(x) for x in hash ]
    return hash