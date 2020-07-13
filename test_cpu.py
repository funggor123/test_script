
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import hashlib
import hmac
import scrypt
import functools, operator
from Library import opencl
from Library.opencl_information import opencl_information
from binascii import unhexlify, hexlify
from collections import deque
from hashlib import pbkdf2_hmac
import time

# ===================================== Test funcs =============================================

def hash_iterations_sha512_test(passwordlist, iters):
    print()
    print("Testing sha512 " + str(iters) + " rounds")

    for i in range(len(passwordlist)):
        passwordlist[i] = hashlib.sha512(passwordlist[i]).digest()

    start = time.time()
    clresult = hash_iterations(passwordlist, hashlib.sha512, iters)
    done = time.time()
    elapsed = done - start
    print("time used", elapsed)

    test_iterations(passwordlist, hashlib.sha512, iters, clresult)

# ===========================================================================================

def test_iterations(passwordlist, hashClass, iters, clResult):
    hashlib_passwords = []
    for password in passwordlist:
        for i in range(iters):
            password = hashClass(password).digest()
        hashlib_passwords.append(password)

    if clResult == hashlib_passwords:
        print("Ok")
    else:
        print("Failed !")
        for i in range(len(passwordlist)):
            if clResult[i] == hashlib_passwords[i]:
                print("#{} succeeded".format(i))
            else:
                print(i)
                print(clResult[i])
                print(hashlib_passwords[i])

def hash_iterations(passwordlist, hashClass, iters):
    hashlib_passwords = []
    for password in passwordlist:
        for i in range(iters):
            password = hashClass(password).digest()
        hashlib_passwords.append(password)
    return hashlib_passwords

def main(argv):
    # Input values to be hashed
    passwordlist = [b'password', b'hmm', b'trolololl', b'madness']

    # Call the tests
    print("cpu test sha512")
    hash_iterations_sha512_test(passwordlist, 10000)

    '''
    for salt in salts:
        print("Using salt: %s" % salt)
        #hash_iterations_md5_test(opencl_algos, passwordlist, 10000)
        #hash_iterations_sha1_test(opencl_algos, passwordlist, 10000)
        #hash_iterations_sha256_test(opencl_algos, passwordlist, 10000)
        start = time.time()
        hash_iterations_sha512_test(opencl_algos, passwordlist, 10000)
        done = time.time()
        elapsed = done - start
        print("time used", elapsed)
    '''


    print("Tests have finished.")

if __name__ == '__main__':
  main(sys.argv)