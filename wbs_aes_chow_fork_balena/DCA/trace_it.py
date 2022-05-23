#!/usr/bin/env python

import sys
sys.path.insert(0, '../../')
from deadpool_dca import *

def processinput(iblock, blocksize):
    return (None, ['%0*x' % (2*blocksize, iblock)])

def qprocessinput(iblock, blocksize):
    return (None, ['-i', '%0*x' % (2*blocksize, iblock)])

def processoutput(output, blocksize):
    return int(''.join([x for x in output.split('\n') if len(x)==32][0]), 16)

filters=[Filter('mem_addr2_rw1', ['R', 'W'], lambda stack_range, addr, size, data: (addr < stack_range[0] or addr > stack_range[1]) and size == 1, lambda addr, size, data: addr & 0xFFFF, '<H')]

T=TracerGrind('../target/aes128', processinput, processoutput, ARCH.amd64, 16, addr_range='0x401AD5-0x4028A7', filters=filters, shell=True, debug=True)
#T=TracerPIN('../target/aes128', processinput, processoutput, ARCH.amd64, 16, addr_range='0x401AD5-0x4028A7', filters=filters, shell=True, debug=True)

# record_info=False because it is not implemented yet
#T=TracerQiling('../target/aes128', qprocessinput, processoutput, ARCH.amd64, 16, addr_range='0x401AD5-0x4028A7', filters=filters, shell=True, record_info=False, debug=True)

T.run(200)
bin2daredevil(keywords=filters,
              configs={'attack_sbox':   {'algorithm':'AES', 'position':'LUT/AES_AFTER_SBOX',    'correct_key':'0x2b7e151628aed2a6abf7158809cf4f3c'},
                       'attack_multinv':{'algorithm':'AES', 'position':'LUT/AES_AFTER_MULTINV', 'correct_key':'0x2b7e151628aed2a6abf7158809cf4f3c'}})
