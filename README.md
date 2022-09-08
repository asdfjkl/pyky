# Kyber512 in Python

## About

- just a toy implementation to better understand the algorithm
- for now, 512 only but should be easily extendable to 768 and 1024 sec levels. 
- ported from the [Go Implementation](https://github.com/kudelskisecurity/crystals-go), so not the fanciest Python code
- not hardened against (timing/other) side channel attacks

## How To Use

Just take a look at `cakem.py`. Functions 

- `kem_keygen512()`, 
- `kem_encaps512(pubkey, seed=None)` and 
- `kem_decaps512(private_key, ciphertext)` 

correspond directly to the [spec](https://pq-crystals.org/). For `kem_encaps` you can optionally provide a custom `m` which is useful for debugging.

Typical kem would be

````
priv, pub = kem_keygen512()
secret1, cipher = kem_encaps512(pub)
secret2 = kem_decaps512(priv, cipher)
````
