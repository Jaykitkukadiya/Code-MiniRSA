# jaykit kukadiya - 40261905

#output
# PS C:\Users\jaykit\Desktop\6110> python rsagen.py
# Wants To Generate New Parameters?(y/n) : y
# --------------------
# Secret Parameters   
# --------------------
# P : 36083
# Q : 42473
# N : 1532553259
# Phi(N) : 1532474704
# --------------------
# Parameters for RSA
# --------------------
# Public Key(e,N) : (20287,1532553259)     
# Private Key(d,N) : (422040527,1532553259)
#  satisfies "ed mod phiN = 1"
# --------------------
# time taken : 0.09s
# 1.Message Encryption/Decryption
# 2.Signature Generation/Verification      
# 3.Exit
# Select Choice : 1
# 1. Encrypt Message
# 2. Decrypt Message
# Select Choice : 1 
# Enter Partner's Public Key(e,N) : (20287,1532553259)
# Enter the meaasge you want to encrypt : Hello, I am Jaykit Kukadiya with student id 40261905
# Cipher Text : [835835861, 1473872586, 327774544, 1052607911, 725421090, 461605335, 1060987766, 1035716595, 456540149, 779108146, 1004472236, 239972498, 1302800869, 360456592, 646675072, 146638975, 776515961, 909459339]
# time taken : 0.0s
# PS C:\Users\jaykit\Desktop\6110> python rsagen.py
# Wants To Generate New Parameters?(y/n) : n
# 1.Message Encryption/Decryption    
# 2.Signature Generation/Verification
# 3.Exit
# Select Choice : 1
# 1. Encrypt Message
# 2. Decrypt Message
# Select Choice : 2 
# Enter Your Private Key(d,N) : (422040527,1532553259)
# Enter List Of Chunks You Want To Decrypt e.g[1,2,3,..] : [835835861, 1473872586, 327774544, 1052607911, 725421090, 461605335, 1060987766, 1035716595, 456540149, 779108146, 1004472236, 
# 239972498, 1302800869, 360456592, 646675072, 146638975, 776515961, 909459339]
# Decrypted Message : Hello, I am Jaykit Kukadiya with student id 40261905
# time taken : 0.01s
# PS C:\Users\jaykit\Desktop\6110>

#constants-----------------------------------------------------------------------------------------------------

#p and q should be 16  bit long
# lower bound of number 32768
# upper bound of number 65535
lower_bound = 32768
upper_bound = 65535
pub_lower_bound = 5000
pub_upper_bound = 32768

#imoprt section------------------------------------------------------------------------------------------------

import random
import time

#function section----------------------------------------------------------------------------------------------

def prime_checker(x: int):
    if x%2 == 0: # number is even, explicitly stating is just for understanding, though this operation is performed in below loop also.
        return False
    for i in range(2,(x-1)//2):
        if x%i == 0: # number is divisible by i
            return False
    return True

def safe_prime_checker(x: int):
    prime_status = prime_checker(x)
    safe_prime_status = False
    if prime_status == True:
        safe_prime_status = prime_checker((2*x)+1)
    return (prime_status, safe_prime_status)

def prime_generator(lower_bound, upper_bound):
    safe_prime_status = False
    while not safe_prime_status: # this is optional, just for better security.
        prime_status = False
        while not prime_status:
            x = random.randint(lower_bound, upper_bound+1)
            prime_status,safe_prime_status = safe_prime_checker(x)
    return x

def gcd(y,x):
    is_gcd = False # True when gcd of e and phiN is 1
    dividend = []
    while not is_gcd:
        tmp = y/x
        dividend.append(int(tmp))
        y = x
        x = round((tmp%1)*y)
        if x == 1:
            return (True,dividend)
        elif x == 0:
            return (False,dividend)

def pubkey_generator(phiN):
    is_gcd = False # True when gcd of e and phiN is 1
    while not is_gcd:
        e = random.randint(pub_lower_bound, pub_upper_bound+1)
        if prime_checker(e) == True:
            is_gcd,dividend = gcd(phiN,e)
        else:
            is_gcd = False
    return e,dividend

def prkey_generator(dividend,phiN):
    x,y = 0,1
    for i in range(0,len(dividend)-1):
        a = dividend[i]
        b = dividend[i+1]
        z = x - (a * y)
        x,y = y,z
    a = dividend[-1]
    z = x - (a * y)
    x,y = y,z
    d = y%phiN
    return d

# gives 2's power to calculate m
# like for m=17, it will return 0 and 4 which means 2^0 + 2^4 = 17
def binary(m):
    mbytes = []
    count = 0
    while m not in (0,1):
        tmp = m/2
        if(int((tmp%1)*2) == 1):
            mbytes.append(count)
        m = int(tmp)
        count += 1
    if m == 1:
        mbytes.append(count) #(some x ** count, 1 means considered else rejected)
    return mbytes,count
    

def power(t,xg3,N):
    res = 1
    while res != xg3:
        res = res*2
        t = t**(2)%N
        # print(res)
    return t

#function for encryption and decryption
# used squre multiply method
def enc_dec(m,k,N):
    xfact = []
    fect,count = binary(k) # k = sum  of 2**element of fects
    xg = []
    for i in fect:
        if i==0: # due to 2^0 = 0 and 2^2^0 = 1, i = 0 is directly added to xfact
            xfact.append(m**(2**i))
        else:
            fector, count = binary(i) # fector again to minimize the calculation. i = sum  of 2**element of fector
            xg.append(fector)
    xgs1 = [] #temporary prm
    xgs2 = [] #temporary prm
    for i1 in xg:
        temp = []
        for xg1 in i1:
            temp.append(2**xg1)
        xgs1.append(temp)
    for i1 in xgs1:
        temp = []
        for xg2 in i1:
            temp.append(2**xg2)
        xgs2.append(temp)
    for i2 in xgs2:
        t = m
        for xg3 in i2:
            # print(i2,mult(t,xg3,N) == (t**xg3)%N )
            t = power(t,xg3,N) # uses squre multiply method
        xfact.append(t)
    xtmp = 1
    for d in xfact:
        xtmp = (xtmp*d)%N
    return xtmp   

#convert hex to decimal
def htdec(m):
    order = 0
    result = 0
    for i in m[::-1]:
        result += i*(16**order)
        order +=1
    return result

#convert string to hex
def sthx(m):
    ascii = ord(m)
    f = ascii//16
    l = ascii%16
    return [f,l]

#convert hex to string
def htos(m):
    result = ""
    for i in range(0, len(m),2):
        result += chr(m[i]*(16**1)+m[i+1]*(16**0))
    return result

#convert decimal to hex
def dtoh(m):
    hx = []
    while m != 0:
        tmp = m/16
        hx.insert(0,int((tmp%1)*16))
        m = int(tmp)
    return htos(hx)

#code section--------------------------------------------------------------------------------------------------

if input("Wants To Generate New Parameters?(y/n) : ") == 'y':
    start_time = time.time()
    # generate rendom p and q
    p = prime_generator(lower_bound,upper_bound)
    q = prime_generator(lower_bound,upper_bound)
    N = p*q

    # due to p and q both are prime
    phiN = (p-1)*(q-1)

    # generate public key
    e,dividend = pubkey_generator(phiN)

    # generate private key
    d = prkey_generator(dividend,phiN)
    # print(f"ed mod phiN = {(e*d)%phiN}")

    print("--------------------\nSecret Parameters\n--------------------")
    print(f"P : {p}\nQ : {q}\nN : {N}\nPhi(N) : {phiN}")
    print("--------------------\nParameters for RSA\n--------------------")
    print(f"Public Key(e,N) : ({e},{N})\nPrivate Key(d,N) : ({d},{N})\nsatisfies \"ed mod phiN = {(e*d)%phiN}\"\n--------------------")

    print(f"time taken : {round(time.time()-start_time,2)}s")


sigperm = input("1.Message Encryption/Decryption\n2.Signature Generation/Verification\n3.Exit\nSelect Choice : ")

if sigperm == '2':
    sigverperm = input("1.Generate Signature\n2.Verify Signature\nSelect Choice : ")
    if sigverperm == '2':
        sigpubve,sigpubvN = eval(input("Enter Partner's Public Key(e,N) : "))
        sigmv = input("Enter Message : ")
        sigvsig = eval(input("Enter signature e.g[1,2,..] : "))
        mtemp = []
        start_time = time.time()
        for c1 in sigvsig:
            mtemp.append(enc_dec(c1,sigpubve,sigpubvN))
        mtemp1 = []
        for m1 in mtemp:
            mtemp1.append(dtoh(m1))
        verifird = ''.join(mtemp1).strip(" ") == sigmv
        if verifird == True:
            print("signature is valid")
        else:
            print("signature is not valid")
        print(f"time taken : {round(time.time()-start_time,2)}s")
    elif sigverperm == '1':
        sigmg = input("Enter Message : ")
        sigprigd,sigprigN = eval(input("Enter Your Private Key(d,N) : "))
        start_time = time.time()
        m = []
        mx=[]
        # pading
        if len(sigmg)%3 != 0:
            for pad in range(0,3-len(sigmg)%3):
                sigmg+=" "
        # spliting and conversion
        for mc in range(0,len(sigmg), 3):
            mx.append("".join([sigmg[mc], sigmg[mc+1], sigmg[mc+2]]))
        for mc1 in mx:
            m.append(htdec(sthx(mc1[0])+sthx(mc1[1])+sthx(mc1[2])))
        c=[]
        #encryption
        for i in m:
            c.append(enc_dec(i,sigprigd,sigprigN)) # message/cipher,key(pub/private),N
        print(f"Message Blocks : {mx}")
        print(f"Signature : {c}")
        print(f"time taken : {round(time.time()-start_time,2)}s")
elif sigperm == '1':
    perm = int(input("1. Encrypt Message\n2. Decrypt Message\nSelect Choice : "))
    if perm == 2:
        d,N = eval(input("Enter Your Private Key(d,N) : "))
        c = eval(input("Enter List Of Chunks You Want To Decrypt e.g[1,2,3,..] : "))
        start_time = time.time()
        mtemp = []
        for c1 in c:
            mtemp.append(enc_dec(c1,d,N))
        mtemp1 = []
        for m1 in mtemp:
            mtemp1.append(dtoh(m1))
        print(f"Decrypted Message : {''.join(mtemp1).strip(' ')}")
        print(f"time taken : {round(time.time()-start_time,2)}s")
    elif perm == 1:
        # encryption  procedure----------------------------------------------------------------------------------------
        e,N = eval(input("Enter Partner's Public Key(e,N) : "))
        m1 = input("Enter the meaasge you want to encrypt : ")
        start_time = time.time()
        m = []
        mx=[]
        # pading
        if len(m1)%3 != 0:
            for pad in range(0,3-len(m1)%3):
                m1+=" "
        # spliting and conversion
        for mc in range(0,len(m1), 3):
            mx.append("".join([m1[mc], m1[mc+1], m1[mc+2]]))
        for mc1 in mx:
            m.append(htdec(sthx(mc1[0])+sthx(mc1[1])+sthx(mc1[2])))
        c=[]
        #encryption
        for i in m:
            c.append(enc_dec(i,e,N)) # message/cipher,key(pub/private),N
        print(f"Message Blocks : {mx}")
        print(f"Cipher Text : {c}")
        print(f"time taken : {round(time.time()-start_time,2)}s")
