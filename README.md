# HQC-chat

A small p2p instant-messenger with EtM-authenticated AES encryption and a homemade implementation of Hamming Quasi-Cyclic Post-Quantum key exchange (https://pqc-hqc.org).

**DISCLAIMER: This project is homemade for _fun_ and is NOT intended for genuine secure communication. DO NOT USE IT WITH _ANY_ EXPECTATION OF SECURITY. If you want to attack it, have fun!**

It uses the RMRS variant of the key exchange as it has smaller key/ciphertext sizes, and both key exchange and data encryption is done at the 256-bit security level. The hash function used for message signing is SHA256, and the hash parameters for the KEM are SHA3_512 and SHA512 (as two functions must be chosen otherwise the scheme will be broken, as mentioned in the whitepaper). The `theta` variable is converted to random bytes as required by means of a SHA512 HMAC-DRBG (dropping the first 256 bytes of the output stream out of habit).

The interface is very basic. One person in the conversation is the passive participant, the other active. The passive participant runs

```
$ hqc-chat.py accept
``` 

and waits for connection. The active participant then runs 

```
$ hqc-chat.py <active ip> <active port>
```

Public keys are exchanged and the participants are able to verify the SHA256 digests. From there, the passive participant will encapsulate a one-time encryption key and send it to the active participant, followed by the active participant generating a one-time signing key and sending it to the passive participant.

At the moment, messages must be exchanged alternating between users. This isn't to do with the crypto, just that using stdin/stdout makes it nearly impossible to have nice separation betwen i/o. Maybe this will be changed later. The passive participant always initiates the converstation.

It uses my own implementation of order-1 Reed-Muller codes using hadamard decoding, which is around 20x faster than the `reedmuller` pip package. However, it requires `reedsolo` for Reed-Solomon decoding and `pycryptodome` for hashes and block ciphers.
