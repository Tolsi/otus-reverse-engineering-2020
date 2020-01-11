#!/usr/bin/env python3
# Sample code for X86 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
import json

from capstone import *

if __name__ == '__main__':
    cs = Cs(CS_ARCH_X86, CS_MODE_16)
    results = {}
    max_commands_bytes = 6
    for i in range(0, pow(2, max_commands_bytes * 8)):
        code = i.to_bytes(max_commands_bytes, byteorder="little")
        disasm_res = list(cs.disasm(code, 0x00))
        if len(disasm_res) > 0:
            res = format("%s %s" % (disasm_res[0].mnemonic, disasm_res[0].op_str))
            if not res in results:
                results[res] = set()
            results[res].add(disasm_res[0].bytes.hex())

    results = {k: v for k, v in results.items() if len(v) > 1}
    with open('results.txt', 'w') as f:
        for k, v in results.items():
            f.write(format("%s: %s\n" % (k, v)))