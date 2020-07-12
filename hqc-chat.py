
from hqc import HQC
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad, unpad
import os

HOST = '127.0.0.1'
PORT = 61337

CIPHER = HQC()

def encapsulate_message(msg, enc_key, sig_key):
    aes_cipher = AES.new(enc_key[:32], AES.MODE_CBC)
    mac = HMAC.new(sig_key, digestmod=SHA256)
    ct = aes_cipher.encrypt(pad(msg, 16))
    mac.update(ct)
    md = mac.digest()
    return aes_cipher.iv + md + ct

def decapsulate_message(msg, enc_key, sig_key):
    iv = msg[:16]
    msg = msg[16:]
    mac_bytes = msg[:32]
    msg = msg[32:]
    mac = HMAC.new(sig_key, digestmod=SHA256)
    mac.update(msg)
    try:
        mac.verify(mac_bytes)
    except:
        return b"ERROR: SIGNATURE FAIL"
    aes_cipher = AES.new(enc_key[:32], AES.MODE_CBC, iv)
    return unpad(aes_cipher.decrypt(msg), 16)

if os.path.isfile('public_key') and os.path.isfile('private_key'):
    with open('public_key', 'rb') as f:
        public_bytes = f.read()
        CIPHER.set_public_key(public_bytes[:CIPHER.n_bytes], public_bytes[CIPHER.n_bytes:])
    with open('private_key', 'rb') as f:
        private_bytes = f.read()
        CIPHER.set_private_key(private_bytes[:CIPHER.n_bytes], private_bytes[CIPHER.n_bytes:])
else:
    CIPHER.keygen()
    with open('public_key', 'wb') as f:
        f.write(CIPHER.get_public_key()[0] + CIPHER.get_public_key()[1])
    with open('private_key', 'wb') as f:
        f.write(CIPHER.get_private_key()[0] + CIPHER.get_private_key()[1])


print ()

print ("===[ HQC chat : a post-quantum communication applet ]===")
print ("A small p2p instant-messenger with EtM-authenticated AES-256 encryption and a homemade implementation of HQC Post-Quantum key exchange (https://pqc-hqc.org)")
print ()
print ("***DISCLAIMER***: This project is homemade as a fun proof-of-concept and is NOT intended for genuine secure communication. DO NOT USE IT WITH _ANY_ EXPECTATION OF SECURITY. If you want to attack it, have fun!")

print ()

if sys.argv[1] == "accept":
    s = socket.socket()
    s.bind(('', PORT))
    s.listen(5)      
    
    print ("Awaiting connections on port %s..." % PORT)           

    c, addr = s.accept()

    pubkey = c.recv(48000)
    print ('Got connection from', addr)
    pk_d = SHA256.new()
    pk_d.update(pubkey)
    print ('Pubkey digest: ', pk_d.hexdigest())

    cont = input("Do you wish to accept? (Y/N): ")
    if cont.upper() == "Y":
        ourpk = CIPHER.get_public_key()
        try:
            CIPHER.set_public_key(pubkey[:CIPHER.n_bytes], pubkey[CIPHER.n_bytes:])
            K,u,v,d = CIPHER.encapsulate()
            c.send(u + v + d)

            c.send(ourpk[0] + ourpk[1])
            CIPHER.set_public_key(ourpk[0], ourpk[1])

            ct = c.recv(48000)
            K_sign = CIPHER.decapsulate(ct[:CIPHER.n_bytes], ct[CIPHER.n_bytes: CIPHER.n_bytes * 2], ct[2 *CIPHER.n_bytes:])
        except:
            print ("\nError during key exchange, exiting")

            print ("Key exchange complete, proceeding with encrypted chat")
            print ()

        while True:
            try:
                c.send(encapsulate_message(input("Send a message: ").encode(), K, K_sign))
                ct = c.recv(48000)
                print ('>',decapsulate_message(ct, K, K_sign).decode())
            except:
                print ("\nError during message transmission, exiting")
                break
    c.close()
else:
    s = socket.socket()

    s.connect((sys.argv[1], int(sys.argv[2])))
    s.send(CIPHER.get_public_key()[0] + CIPHER.get_public_key()[1])
    
    try:
        ct = s.recv(48000)
        K = CIPHER.decapsulate(ct[:CIPHER.n_bytes], ct[CIPHER.n_bytes: CIPHER.n_bytes * 2], ct[2 *CIPHER.n_bytes:])
        
        pubkey = s.recv(48000)
    except:
        print ("\nError during key exchange, exiting")


    pk_d = SHA256.new()
    pk_d.update(pubkey)
    print ('Pubkey digest: ', pk_d.hexdigest())

    cont = input("Do you wish to accept? (Y/N): ")
    if cont.upper() == "Y":
        try:
            CIPHER.set_public_key(pubkey[:CIPHER.n_bytes], pubkey[CIPHER.n_bytes:])
            K_sign,u,v,d = CIPHER.encapsulate()
            s.send(u + v + d)
        except:
            print ("\nError during key exchange, exiting")

        print ("Key exchange complete, proceeding with encrypted chat")
        print ()


        while True:
            try:
                ct = s.recv(48000)
                print ('>',decapsulate_message(ct, K, K_sign).decode())
                s.send(encapsulate_message(input("Send a message: ").encode(), K, K_sign))
            except:
                print ("\nError during message transmission, exiting")
                break
    s.close() 
