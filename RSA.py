# -*- coding: utf-8 -*-
"""
Created on Tue Apr 17 17:30:53 2018

@author: ahmed
"""


# to run the code , click run and choose the number of bits of p and q , 
#then enter your msg to be encrypted


import random

# Returns True if num is a prime number.
def rabinMiller(num):

    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1

    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True



# Return True if num is a prime number. This function does a quicker
# prime number check before calling rabinMiller().
def isPrime(num):
    
    if (num < 2):
        return False # 0, 1, and negative numbers are not prime

    # the first few dozen prime numbers
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True

    # See if any of the low prime numbers can divide num
    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    # If all else fails, call rabinMiller() to determine if num is a prime.
    return rabinMiller(num)

# Return a random prime number of keysize bits in size.
def generateLargePrime(keysize=512):
    
    while True:
        num = random.randrange(2**(keysize-1), 2**(keysize))
        if isPrime(num):
            return num


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
    
    
def modInverse(a, m) : # using EEA
    m0 = m
    y = 0
    x = 1
 
    if (m == 1) :
        return 0
 
    while (a > 1) :
 
        # q is quotient
        q = a // m
 
        t = m
 
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
 
        # Update x and y
        y = x - q * y
        x = t
 
    # Make x positive
    if (x < 0) :
        x = x + m0
 
    return x


def generate_keypair(p, q):
    if not (isPrime(p) and isPrime(q)):
        raise ValueError('Both numbers must be prime.')
    if p == q:
        raise ValueError('p and q cannot be equal')
    
    n = p * q

    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    print('n is ' , n)
    print('phi is ' , phi)    
    print('gcd is ' , g)
    print('\n\n')
    
    #Use Extended Euclid's Algorithm to generate the private key
    d = modInverse(e, phi)
    
    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


#Computes (a^r) mod P  by decomposing r into binary
def SqrAndMul(a, r, P):  
    x = 1
    while r > 0:
        if r % 2 != 0:
            x = (x * a) % P
        a = (a * a) % P
        r //= 2
    return x


def encrypt(pk, plaintext):
    #Unpack the key into it's components
    key, n = pk
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    #cipher = [(ord(char) ** key) % n for char in plaintext]
    cipher = [SqrAndMul(ord(char) , key , n) for char in plaintext]
    #Return the array of bytes
    return cipher


def decrypt(pk, ciphertext):
    #Unpack the key into its components
    key, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    #plain = [chr((char ** key) % n) for char in ciphertext]
    plain = [chr(SqrAndMul(char , key , n)) for char in ciphertext]
    #Return the array of bytes as a string
    return ''.join(plain)



def decryptCRT(d , cipherText , p , q):
    x = ['']
    for i in cipherText: 
        yp , yq = [i % p , i % q]
        dp ,dq = [d[0] % (p-1) , d[0] % (q-1)]
        xp , xq = [SqrAndMul(yp,dp,p) , SqrAndMul(yq,dq,q)]
        cp , cq = [modInverse(p%q,q),modInverse(q%p,p)]
        temp = ((q*cp*xp) + (p*cq*xq)) % (p*q)
        
        print('with CRT temp = ' ,  temp , ' and char is ' , chr(temp))
        x.append((temp))
        
    return ''.join(x)



if __name__ == '__main__':
    '''
    Detect if the script is being run directly by the user
    '''
    print ("RSA Encrypter/ Decrypter")
   # p = int(input("Enter a prime number (17, 19, 23, etc): "))
   # q = int(input("Enter another prime number (Not one you entered above): "))
    
   
    input_p = input("choose the number of bits of p: \n")
    input_q = input("choose the number of bits of q: \n")
    print ("Generating your public/private keypairs now . . .\n")
    p = generateLargePrime(int(input_p))
    q = generateLargePrime(int(input_q))
    print('p is ' , p , '\nq is ' , q )
    public, private = generate_keypair(p, q)
    print ("\nYour public key is ", public ," and your private key is ", private)
    message = input("Enter a message to encrypt with your public key: \n")
    encrypted_msg = encrypt(public, message)
    print ("\nYour encrypted message is: ")
    print (''.join(map(lambda x: str(x), encrypted_msg)) , '\n')
    print ("Decrypting message with private key ", public ," . . .\n")
    print ("Your message is:")
    print (decrypt(private, encrypted_msg))
    
    

