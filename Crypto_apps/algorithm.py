#!/usr/bin/python
#coding: utf-8

import string
import base64
import codecs
import time
import hashlib
import rsa
from Crypto.Cipher import AES
import sys
from binascii import b2a_hex,a2b_hex
from Crypto.Cipher import DES
from Crypto import Random
import binascii

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
proot = 2

#求逆元函数
def ex_gcd(a,b):
    if a == 0 and b == 0:
        return (-1,0,0)
    elif b == 0:
        return (a,1,0)
    d,y,x = map(int,ex_gcd(b,a%b))
    y -= a//b * x
    return (d,x,y)

#快速幂
def powmod(a,b,MOD):
    res = 1
    if a >= MOD:
        a = a % MOD
    while b > 0:
        if (b&1) == 1:
            res = res * a
            if res >= MOD:
                res = res % MOD
        a = a * a
        if a >= MOD:
            a = a % MOD
        b = b >> 1
    return res

#仿射加密
class Radiate():
    
    def encryption(self,plaintext, KeyConf):
        strr = ''
        KeyConf = KeyConf.decode('utf-8')
        plaintext = plaintext.decode('utf-8')
        a = int(KeyConf.split('\n')[0])
        b = int(KeyConf.split('\n')[1])
        for i in plaintext:
            temp = ord(i)-97
            t = (temp * a + b) % 26
            te = chr(t + 97)
            strr += te
        return strr
    
    def decryption(self, ciphertext, KeyConf):
        strr = ''
        KeyConf = KeyConf.decode('utf-8')
        ciphertext = ciphertext.decode('utf-8')
        a = int(KeyConf.split('\n')[0])
        b = int(KeyConf.split('\n')[1])
        d, x, y = map(int,ex_gcd(a, 26))
        aa = (x%26 + 26) % 26
        for i in ciphertext:
            temp = ord(i) -97
            t = ((temp - b + 26) % 26) * aa % 26
            te = chr(t + 97)
            strr += te
        return strr


class des_crypto():
            
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        
    def encrypt(self,decryptText):
        cipher1 = DES.new(self.key,DES.MODE_CBC,self.iv)
        encrypt_msg =  cipher1.encrypt(decryptText)
        return encrypt_msg
    
    def decrypt(self,ecryptText):
        cipher2 = DES.new(self.key,DES.MODE_CBC,self.iv)
        decrypt_msg = cipher2.decrypt(ecryptText)
        return decrypt_msg


class aes_crypto():
    def __init__(self,key):
        self.key = key
        self.mode = AES.MODE_CBC

    def encrypt(self,text):
        cipher = AES.new(self.key,self.mode,self.key)
        length = 16
        count = len(text)
        if count % length != 0:
            add = length - (count % length)
        else:
            add = 0
        text = text + (b'\0'*add)
        ciphertext = cipher.encrypt(text)
        return ciphertext

    def decrypt(self,text):
        cipher = AES.new(self.key,self.mode,self.key)
        plain = cipher.decrypt(text)
        plain = plain.rstrip(b'\0')
        return plain

def bytes2int(bts):
    res = 0
    for i in bts:
        res = res * 256 + int(i)
    return res

class rsa_crypto():
    def __init__(self,pubkey = None, privkey = None):
        if (pubkey == None and privkey == None):
            self.pubkey, self.privkey = rsa.newkeys(512)
        else:
            self.pubkey, self.privkey = pubkey,privkey

    def rsa_encrypt(self,string):
        ne = str(self.pubkey).split(',')
        n = int(ne[0][10:])
        e = int(ne[1][1:-1])
        hexstr = bytes2int(string)
        cryptot = ("%x"%powmod(hexstr,e,n))
        if len(cryptot)%2 == 1:
            cryptot = '0'+cryptot
        return a2b_hex(cryptot)
        
    def rsa_decrypt(self,string):
        nedpq = str(self.privkey).split(',')
        n = int(nedpq[0][11:])
        d = int(nedpq[2][1:])
        hexstr = bytes2int(string)
        content = powmod(hexstr,d,n)
        content = ("%x"%content)
        if len(content)%2 == 1:
            content = '0'+content
        return a2b_hex(content)

class Md5():
    def get_token(self,Str):
        md5str = Str
        Str = Str.encode("utf-8")
        m1 = hashlib.md5(Str)
        m1.update(md5str.encode("utf-8"))
        token = m1.hexdigest()
        return token

 
class RC4(object):
    
    def __init__(self, key = None):
        if not key:
            self.key = 'default_key'
        self.key = key.decode('utf-8')
        self._init_slist()
    
    #初始化s列表 单下划线开头表示权限为protected
    def _init_slist(self):
        #初始化s列表
        self.slist = [i for i in range(256)]
        
        #初始化t列表
        length = len(self.key)
        t = [ord(self.key[i%length]) for i in range(256)]
             
        #用t产生s的初始置换
        j = 0
        for i in range(256):
            j = (j + self.slist[i] + t[i])%256
            self.slist[i], self.slist[j] = self.slist[j], self.slist[i]
 
    #加解密
    def do_crypt(self, string):
        i = 0
        j = 0
        result = []
        string = string.decode('utf-8')
        for s in string:
            i = (i + 1) % 256
            j = (j + self.slist[j])%256
            self.slist[i], self.slist[j] = self.slist[j], self.slist[i]
            t = (self.slist[i] + self.slist[j])%256
            result.append(chr(ord(s)^self.slist[t]))
        return (''.join(result)).encode('utf-8')
        

def get_str_bits(s):
    lis = []
    for i in s:
        j,cnt = i,8
        while cnt > 0:
            lis.append(j & 1)
            j = j >> 1
            cnt = cnt - 1
    return lis

class LFSR():
    def __init__(self, c = [], a = [],lenc = 0):
        self.a = a
        self.c = c
        self.lenc = lenc
        lena = len(a)
        if lena < lenc:
            cnta = (lenc - lena) // lena + 1
            for i in range(cnta):
                self.a.extend(a)

    def LeftShift(self):
        lastb = 0
        lenc = self.lenc
        for i in range(lenc):
            lastb = lastb ^ (self.a[i] & self.c[i])
        b = self.a[1:]
        outp = self.a[0]
        b.append(outp)
        self.a = b
        return outp

class crypto_LFSR():
    def __init__(self, key, lfsr1 = [], lfsr2 = []):
        Keymap = get_str_bits(key)
        lenk = len(Keymap)
        self.lfsr1 = LFSR(Keymap, lfsr1, lenk)
        self.lfsr2 = LFSR(Keymap, lfsr2, lenk)
        self.Key = Keymap
        self.lc = 0

    def GetBit(self):
        ak = self.lfsr1.LeftShift()
        bk = self.lfsr2.LeftShift()
        ck = ak ^ ((ak ^ bk) & self.lc)  # JK 触发器
        self.lc = ck
        return ck

    def do_crypt(self,LFSR_msg):
        text = []
        for i in LFSR_msg:
            j,cnt = i, 8
            tmp = []
            while cnt > 0:
                tmp.append(self.GetBit() ^ (j & 1))
                j  = j >> 1
                cnt = cnt - 1
            res = 0
            for iti in range(7,-1,-1):
                res = res << 1
                res = res + tmp[iti]
            text.append(res)
        return bytes(text)

def calk(mk,yk):
    global p
    return powmod(yk,mk,p)

def HASH(msg,opporsaPubK):
    global p,proot
    msgint = bytes2int(msg.encode('utf-8'))
    msg = ("%x"%powmod(proot,msgint,p)).upper()
    msg = (768-len(msg)) * '0' + msg
    token = Md5().get_token(msg)
    rst = opporsaPubK.rsa_encrypt(a2b_hex(token))
    rst = str(b2a_hex(rst)).upper()[2:-1]
    rst = (128-len(rst)) * '0' + rst
    return msg + rst

if __name__ == '__main__':
    a = '[213,34234,234234,21312,6575675,2312]'
    b = a.split(',')
    for i in b:
        print(i)