#!/usr/bin/env python3

from capstone import Cs
from qiling import Qiling
from qiling.const import QL_VERBOSE
import argparse

from unicorn.unicorn_const import UC_MEM_WRITE, UC_MEM_READ

traces = []

def mem_read(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
    # only read accesses are expected here
    assert access == UC_MEM_READ

    traces.append(f'[R] {address:016x} size= {size:d} value={value:016x}\n')

def mem_write(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
    # only write accesses are expected here
    assert access == UC_MEM_WRITE

    traces.append(f'[W] {address:016x} size= {size:d} value={value:016x}\n')

def start_hooks(ql, *args, **kw):
    if len(ql._hook)<2:
        ql.hook_mem_write(mem_write)
        ql.hook_mem_read(mem_read)
    
def stop_hooks(ql, *args, **kw):
    ql._hook = {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Qiling Tracer')
    # make sure you set full path to the target, otherwise it may crash
    parser.add_argument("-t", dest="target", required=True)
    parser.add_argument("-i", dest="input", required=True)
    parser.add_argument("-of", dest="outputfile", required=True)
    parser.add_argument("-f", dest="filters", required=False)
    # mips, arm, x8664 works fine. aarch64 has an issue
    parser.add_argument("-r", dest="rootfs", required=True)


    args = parser.parse_args()

    argv = [args.target, args.input]
    ql = Qiling(argv, args.rootfs, verbose=QL_VERBOSE.DEFAULT, multithread=True)


    if args.filters:
        filters = [int(i, 16) for i in args.filters.split('-')]
        ql.hook_address(start_hooks, filters[0])
        ql.hook_address(stop_hooks, filters[1])
    else:
        # captures every read and write; not recommended
        ql.hook_mem_write(mem_write)
        ql.hook_mem_read(mem_read)

    ql.run()

    with open(args.outputfile, 'w') as of:
        of.writelines(traces)
