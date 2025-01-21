# NOT MAINTAINED ANYMORE

I wrote this implementation three years ago to understand Kyber - when it was a hot candidate to be selected in the NIST process. Meanwhile, there are 
other, better maintained implementations out there.

If you are looking for a clean, straight-forward and well-tested implementation of Kyber (now standardized as ML-KEM) I recommend the [Python](https://github.com/mjosaarinen/py-acvp-pqc) implementation of Markku-Juhani O. Saarinen.

# Crystals-Kyber in Python

## About

- just a toy implementation to better understand the algorithm
- all three 512, 768 and 1024 sec levels. 
- ported from the [reference](https://github.com/pq-crystals/kyber) and the [Go Implementation](https://github.com/kudelskisecurity/crystals-go), so not the fanciest Python code
- not hardened against (timing/other) side channel attacks
- test coverage is poor, use at your own risk

## How To Use

Just take a look at `ccakem.py`. Functions 

- `kem_keygenXXX()`, 
- `kem_encapsXXX(pubkey, seed=None)` and 
- `kem_decapsXXX(private_key, ciphertext)` 

correspond directly to the [spec](https://pq-crystals.org/). For `kem_encaps` you can optionally provide a custom `seed` which is useful for debugging.

Typical kem, e.g. 512 sec level, would be

````
priv, pub = kem_keygen512()
secret1, cipher = kem_encaps512(pub)
secret2 = kem_decaps512(priv, cipher)
````
