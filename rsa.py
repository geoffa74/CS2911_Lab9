# coding=utf-8

#: ## Lab 9 ##
#: 
#: CS-2910 Network Protocols  
#: Dr. Yoder 
#: Fall quarter 2016-2017
#: 
#: | Team members (username) |
#: |:------------------------|
#: | Jon Sonderman (sondermanjj)  |
#: | Geoff AppelBaum (appelbaumgl)   |
#: 

import random
import sys
import time
import numpy


# Use these named constants as you write your code
MAX_PRIME = 0b11111111  # The maximum value a prime number can have
MIN_PRIME = 0b11000001  # The minimum value a prime number can have 
PUBLIC_EXPONENT = 17  # The default public exponent


#
# Provide the user with a variety of encryption-related actions
#
def main():
    # Get chosen operation from the user.
    action = input("Select an option from the menu below:\n"
                   "(1-CK) create_keys\n"
                   "(2-CC) compute_checksum\n"
                   "(3-VC) verify_checksum\n"
                   "(4-EM) encrypt_message\n"
                   "(5-DM) decrypt_message\n"
                   "(6-BK) break_key\n "
                   "Please enter the option you want:\n")
    # Execute the chosen operation.
    if action in ['1', 'CK', 'ck', 'create_keys']:
        create_keys_interactive()
    elif action in ['2', 'CC', 'cc', 'compute_checksum']:
        compute_checksum_interactive()
    elif action in ['3', 'VC', 'vc', 'verify_checksum']:
        verify_checksum_interactive()
    elif action in ['4', 'EM', 'em', 'encrypt_message']:
        encrypt_message_interactive()
    elif action in ['5', 'DM', 'dm', 'decrypt_message']:
        decrypt_message_interactive()
    elif action in ['6', 'BK', 'bk', 'break_key']:
        break_key_interactive()
    else:
        print("Unknown action: '{0}'".format(action))


#
# Create new public keys
#
# Returns the private key for use by other interactive methods
#
def create_keys_interactive():
    key_pair = create_keys()
    pub = get_public_key(key_pair)
    priv = get_private_key(key_pair)
    print("Public key: ")
    print(pub)
    print("Private key: ")
    print(priv)
    return priv


#
# Compute the checksum for a message, and encrypt it
#  
def compute_checksum_interactive():
    priv = create_keys_interactive()

    message = input('Please enter the message to be checksummed: ')

    hash = compute_checksum(message)
    print('Hash:', "{0:04x}".format(hash))
    cypher = apply_key(priv, hash)
    print('Encrypted Hash:', "{0:04x}".format(cypher))


#
# Verify a message with its checksum, interactively
#
def verify_checksum_interactive():
    pub = enter_public_key_interactive()
    message = input('Please enter the message to be verified: ')
    recomputed_hash = compute_checksum(message)

    string_hash = input('Please enter the encrypted hash (in hexadecimal): ')
    encrypted_hash = int(string_hash, 16)
    decrypted_hash = apply_key(pub, encrypted_hash)
    print('Recomputed hash:', "{0:04x}".format(recomputed_hash))
    print('Decrypted hash: ', "{0:04x}".format(decrypted_hash))
    if recomputed_hash == decrypted_hash:
        print('Hashes match -- message is verified')
    else:
        print('Hashes do not match -- has tampering occured?')


#
# Encrypt a message
#
def encrypt_message_interactive():
    message = input('Please enter the message to be encrypted: ')
    pub = enter_public_key_interactive()
    encrypted = ''
    for c in message:
        encrypted += "{0:04x}".format(apply_key(pub, ord(c)))
    print("Encrypted message:", encrypted)


#
# Decrypt a message
#
def decrypt_message_interactive(priv=None):
    encrypted = input('Please enter the message to be decrypted: ')
    if priv is None:
        priv = enter_key_interactive('private')
    message = ''
    for i in range(0, len(encrypted), 4):
        enc_string = encrypted[i:i + 4]
        enc = int(enc_string, 16)
        dec = apply_key(priv, enc)
        if dec >= 0 and dec < 256:
            message += chr(apply_key(priv, enc))
        else:
            print('Warning: Could not decode encrypted entity: ' + enc_string)
            print('         decrypted as: ' + str(dec) + ' which is out of range.')
            print('         inserting _ at position of this character')
            message += '_'
    print("Decrypted message:", message)


#
# Break key, interactively
#
def break_key_interactive():
    pub = enter_public_key_interactive()
    priv = break_key(pub)
    print("Private key:")
    print(priv)
    decrypt_message_interactive(priv)


#
# Prompt user to enter the public modulus.
#
# returns the tuple (e,n)
#    
def enter_public_key_interactive():
    print('(Using public exponent = ' + str(PUBLIC_EXPONENT) + ')')
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return (PUBLIC_EXPONENT, modulus)


#
# Prompt user to enter the exponent and modulus of a key
#
# key_type - either the string 'public' or 'private' -- used to prompt the user on how
#            this key is interpretted by the program.
#
# returns the tuple (e,n)
#    
def enter_key_interactive(key_type):
    string_exponent = input('Please enter the ' + key_type + ' exponent (decimal): ')
    exponent = int(string_exponent)
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return (exponent, modulus)


#
# Compute simple hash
#
# Given a string, compute a simple hash as the sum of characters
# in the string.
#
# (If the sum goes over sixteen bits, the numbers should "wrap around"
# back into a sixteen bit number.  e.g. 0x3E6A7 should "wrap around" to
# 0xE6A7)
#
# This checksum is similar to the internet checksum used in UDP and TCP
# packets, but it is a two's complement sum rather than a one's
# complement sum.
#
# Returns the checksum as an integer 
#
def compute_checksum(string):
    total = 0
    for c in string:
        total += ord(c)
    total %= 0x8000  # Guarantees checksum is only 4 hex digits
    # How many bytes is that?
    #
    # Also guarantees that that the checksum will
    # always be less than the modulus.
    return total


# ---------------------------------------
# Do not modify code above this line
# ---------------------------------------

#
# Create the public and private keys.
#
# Returns the keys as a three-tuple:
#
#  (e,d,n)
#
def create_keys():

    #Generate the random p and q so that it is a prime, (p-1)%e != 0, and it is between the min and max
    p = 4
    q = 4

    primes = primesfrom3to(MAX_PRIME)
    while((not is_prime(p)) or ((p-1)%PUBLIC_EXPONENT) == 0):
        p = random.randint(int(MIN_PRIME), int(MAX_PRIME))

    while ((not is_prime(q)) or ((q - 1) % PUBLIC_EXPONENT) == 0 or q == p):
        q = random.randint(int(MIN_PRIME), int(MAX_PRIME))

    #Calculate the modulues n and totient z
    n = p*q
    z = (p-1)*(q-1)
    d = 1
    while ((d*PUBLIC_EXPONENT)%z != 1):
        d += 1

    return (PUBLIC_EXPONENT, d, n)

#
# Apply the key, given as a tuple (e,n) or (d,n) to the message.
#
# This can be used both for encryption and decription.
#
# Returns the message with the key applied. For example,
# if given the public key and a message, encrypts the message
# and returns the ciphertext.
#
def apply_key(key, m):

    message = (m ** key[0])%key[1]
    return message

#
# Break a key.  Given the public key, find the private key.
# Factorizes the modulus n to find the prime numbers p and q.
#
# You can follow the steps in the "optional" part of the in-class
# exercise.
#
# pub - a tuple containing the public key (e,n)
#
# returns a tuple containing the private key (d,n)
#
def break_key(pub):
    start = time.time()
    n = pub[1]
    p = 1
    q = 1

    #Brute force attack n, finding the original p and q
    primes = primesfrom3to(n)
    for first in primes:
        p = first
        for second in primes:
            q = second
            if (p*q == n):
                break
        if (p*q == n):
            break

    end = time.time()
    endtime = end - start
    print("Time to break: "+str(endtime) + " seconds")
    print();
    z = (p - 1) * (q - 1)
    d = 1
    while ((d * PUBLIC_EXPONENT) % z != 1):
        d += 1
    return (d,n)

def is_prime(n):
  if n == 2 or n == 3: return True
  if n < 2 or n%2 == 0: return False
  if n < 9: return True
  if n%3 == 0: return False
  r = int(n**0.5)
  f = 5
  while f <= r:
    if n%f == 0: return False
    if n%(f+2) == 0: return False
    f +=6
  return True

def primesfrom3to(n):
    """ Returns a array of primes, 3 <= p < n """
    sieve = numpy.ones(round(n/2), dtype=numpy.bool)
    for i in range(3,int(n**0.5)+1,2):
        if sieve[round(i/2)]:
            sieve[round(i*i/2)::i] = False
    return 2*numpy.nonzero(sieve)[0][1::]+1


# ** Do not modify code below this line.

#
# Pulls the public key out of the tuple structure created by
# create_keys()
#
def get_public_key(key_pair):
    return (key_pair[0], key_pair[2])

#
# Pulls the private key out of the tuple structure created by
# create_keys()
#
def get_private_key(key_pair):
    return (key_pair[1], key_pair[2])


main()
