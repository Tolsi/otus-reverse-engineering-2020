#!/usr/bin/env python3

import string
from itertools import chain, product

# md5 FB42BFAD815A9563B9F6FDD362B47F70

def bruteforce(charset, maxlength):
    return (''.join(candidate)
            for candidate in chain.from_iterable(product(charset, repeat=i)
                                                 for i in range(1, maxlength + 1)))

# int __cdecl sub_438010(int a1)
# {
#     unsigned int v2; // [esp+DCh] [ebp-2Ch]
# signed int i; // [esp+F4h] [ebp-14h]
# int v4; // [esp+100h] [ebp-8h]
#
# v4 = 0;
# v2 = -1;
# while ( *(_BYTE *)(v4 + a1) )
#     {
#     v2 ^= *(char *)(v4 + a1);
#     for ( i = 7; i >= 0; --i )
#     v2 = -(v2 & 1) & 0xEDB88320 ^ (v2 >> 1);
#     v4++;
#     }
#     return ~v2;
# }

def unsigned(signed, bits):
    return signed % (2 ** bits)

def rshift(val, n, bits): return unsigned(val, bits) >> n

def processUsername(username):
    username = list(username)
    result = -1
    for i in range(0, len(username)):
        result ^= ord(username[i])
        for j in range(0, 8):
            andOne = result & 1
            negAndOne = -(andOne)
            # fuck this shift >_<
            shrOne = rshift(result, 1, 32)
            andWtf = negAndOne & 0xEDB88320
            result = shrOne ^ andWtf
    return ~result & 0xFF

# int __cdecl sub_4380E0(char *a1)
# {
#     signed int i; // [esp+D0h] [ebp-20h]
# signed int v3; // [esp+DCh] [ebp-14h]
# int v4; // [esp+E8h] [ebp-8h]
#
# v4 = 0;
# v3 = j__strlen(a1);
# for ( i = 0; i < v3; ++i )
# v4 += a1[i] ^ 0x99;
# return v4;
# }
def processKey(key):
    key = list(key)
    v4 = 0
    for i in range(0, len(key)):
        v4 += ord(key[i]) ^ 0x99
    return v4 & 0xFF

#     char __cdecl sub_437F20(char *a1)
# {
#     signed int i; // [esp+D0h] [ebp-14h]
# signed int v3; // [esp+DCh] [ebp-8h]
#
# v3 = j__strlen(a1);
# for ( i = 0; i < v3; ++i )
# {
# if ( (a1[i] < 65 || a1[i] > 90) && (a1[i] < 48 || a1[i] > 57) && (a1[i] < 97 || a1[i] > 122) )
# return 0;
# }
# return 1;
# }
def isValidString(username):
    username = list(username)
    for i in range(0, len(username)):
        c = ord(username[i])
        # c < 'A' || c > 'Z'
        # c < '0' || c > '9'
        # c < 'a' || c > 'z'
        if (c < 65 or c > 90) and \
                (c < 48 or c > 57) and\
                (c < 97 or c > 122):
            return False
    return True

# v9 = "[-] Login or password is not correct\n";
# v8 = "[+] Good work!\n";
# v6 = 0;
# j__memset(&v7, 0, 0x103u);
# v4 = 0;
# j__memset(&v5, 0, 0x103u);
# sub_43441C("login: ");
# sub_433445("%s", &v6);
# sub_43441C("%s");
# sub_433445("%s", &v4);
# if ( (unsigned __int8)sub_432D01(&v6) && (unsigned __int8)sub_432D01(&v4) && (unsigned __int8)checkKey((int)&v6, &v4) )
# sub_43441C(v8);
# else
# sub_43441C(v9);

def doIt():
    assert processUsername('aa') == 0xD7
    assert processKey('aa') == 0xF0
    assert processKey('N') == 0xD7

    username = input('Enter an username: ')

    if not isValidString(username) or len(username) > 30:
        print('Invalid username!')
        return

    usernameValue = processUsername(username)
    for i in range(1, 10):
        for attempt in bruteforce(string.digits + string.ascii_letters, i):
            keyValue = processKey(attempt)
            if keyValue == usernameValue:
                print('Key: ' + attempt)
                return

if __name__ == '__main__':
    doIt()