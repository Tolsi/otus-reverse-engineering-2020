#!/usr/bin/env python3

import string
from itertools import chain, product

# md5 66F573036F8B99863D75743EFF84F15D

def bruteforce(charset, maxlength):
    return (''.join(candidate)
            for candidate in chain.from_iterable(product(charset, repeat=i)
                                                 for i in range(1, maxlength + 1)))


# int __usercall processUsername@<eax>(int a1@<ebp>, int result@<edi>, unsigned __int8 *username)
# {
#     unsigned __int8 *i; // esi
# char symbol; // al
#
# for ( i = username; ; ++i )
# {
#     symbol = *i;
# if ( !*i )
# {
# bytesSumToEdi(username);
# return result ^ 0x5678;
# }
# if ( (unsigned __int8)symbol < 0x41u )
#     return MessageBoxA(*(HWND *)(a1 + 8), aNoLuckThereMat, aNoLuck, 0x30u);
# if ( (unsigned __int8)symbol >= 0x5Au )
#     alMinus32(symbol, i);
# }
# }

def processUsername(username):
    username = list(username.upper())
    total = 0
    for i in range(0, len(username)):
        if (username[i] >= 'Z'):
            username[i] = chr(ord(username[i]) - 0x20)
        total = total + ord(username[i])
    return total ^ 0x5678


# char __cdecl keyCheck(byte[] a1)
# {
#     int v1 = 0; // eax
#     int v2 = 0; // edi
#     int v3 = 0; // ebx
#     _BYTE *i; // esi
#
# for ( i = a1; ; ++i )
# {
#     if ( !i )
#         break;
#     v2 = (*i - 48) + 10 * v2;
# }
# return v1;
# }
def processKey(key):
    key = list(key)
    res = 0
    for i in range(0, len(key)):
        res = res * 10 + (ord(key[i]) - 0x30)
    return res ^ 0x1234

def doIt():
    assert processUsername('aa') == 22266
    assert processKey('aa') == 4143

    username = input('Enter an username: ')

    if (len(username) > 30):
        print('Invalid username!')
        return

    usernameValue = processUsername(username)
    for attempt in bruteforce(string.digits, 10):
        if processKey(attempt) == usernameValue:
            print('Key: ' + attempt)
            return

if __name__ == '__main__':
    doIt()