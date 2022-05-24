#!/usr/bin/env python

import sys, glob, os
sys.path.insert(0, '../../')
from deadpool_dca import *
import argparse

def processinput(iblock, blocksize):
    return (None, ['%0*x' % (2*blocksize, iblock)])

def qprocessinput(iblock, blocksize):
    return (None, ['-i', '%0*x' % (2*blocksize, iblock)])

def processoutput(output, blocksize):
    try:
        return int(''.join([x for x in output.split('\n') if len(x)==32][0]), 16)
    except:
        print("There must have been some error, could not return anything")
        return 0


parser = argparse.ArgumentParser(prog='./trace_it.py', description='Capture and prepare application traces for the daredevil.')
parser.add_argument('N', type=int, help='number of traces to capture')
parser.add_argument('-f', '--filter', metavar='address_range', dest='range', required=False, default=None, help='filter traces to capture only this address range')
parser.add_argument('-t', '--tracer', metavar='tracer_index', dest='tracer', default=0, type=int, choices=[0, 1, 2], help='tracer to use (default=0): TracerGrind=0, TracerPIN=1, TracerQiling=2')
parser.add_argument('-a', '--arch', metavar='architecture', dest='arch', default="amd64", required=False, choices=["i386", "amd64", "arm", "arm64", "mips"], help='set architecture: "i386", "amd64", "arm", "arm64" or "mips"')
parser.add_argument('-x', '--exec', metavar='executable', dest='executable', required=True, help='file to be executed (set full path)')

args = parser.parse_args()

tracers=[TracerGrind, TracerPIN, TracerQiling]

# make sure you only choose "mem_addr*" filters because currently qtracer.py doesn't return bytes read by program correctly so other filters won't work
filters=[Filter('mem_addr2_rw1', ['R', 'W'], lambda stack_range, addr, size, data: (addr < stack_range[0] or addr > stack_range[1]) and size == 1, lambda addr, size, data: addr & 0xFFFF, '<H')]

pi = processinput
arch = ARCH.amd64

if args.arch == "i386":
    arch = ARCH.i386
elif args.arch == "arm":
    arch = ARCH.arm
elif args.arch == "arm64":
    # this arch doesn't work yet
    arch = ARCH.arm64
elif args.arch == "mips":
    arch = ARCH.mips


if args.tracer==2:
    pi=qprocessinput


if args.range:
    T = tracers[args.tracer](args.executable, pi, processoutput, arch, 16, addr_range=args.range, filters=filters, shell=True, debug=True, record_info=False)
else:
    T = tracers[args.tracer](args.executable, pi, processoutput, arch, 16, filters=filters, shell=True, debug=True, record_info=False)


T.run(args.N)

# an error sometimes arises when using Qiling Tracer and mips as architecture
# so make sure to clean those traces 
if args.tracer==2:
    for f in glob.glob("*00000000000000000000000000000000.bin"):
        os.remove(f)

bin2daredevil(keywords=filters,
              configs={'attack_sbox':   {'algorithm':'AES', 'position':'LUT/AES_AFTER_SBOX',    'correct_key':'0x2b7e151628aed2a6abf7158809cf4f3c'},
                       'attack_multinv':{'algorithm':'AES', 'position':'LUT/AES_AFTER_MULTINV', 'correct_key':'0x2b7e151628aed2a6abf7158809cf4f3c'}})
