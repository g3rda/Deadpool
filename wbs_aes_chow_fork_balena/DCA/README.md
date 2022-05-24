Use TracerGrind/TracerPIN/TracerQiling to acquire execution traces with `trace_it.py`.

Usage
-----

Before running make sure the pathes to tracer(s) and rootfs in deadpool_dca.py are correct.

usage:
`./trace_it.py [-h] [-r address_range] [-t tracer_index] [-a architecture] -x executable N`

example:
`./trace_it.py -r 0x01055c-0x010de4 -t 2 -a arm -x /home/gg/Deadpool/wbs_aes_chow_fork_balena/target/aes128-arm  250`


Address ranges to use
---------------------

Address ranges to capture for each architecture for this target:
x86-64  - 0x401AD5-0x4028A7
aarch64 - 0x4006d4-0x400f98
arm     - 0x01055c-0x010de4
mips    - 0x4007a0-0x401298
powerpc - 0x100005bc-0x10000f90

note: architectures that currently don't work - aarch64 (there is an error during execution) and powerpc (it is not supported by qiling)

Executing the differential analysis on the converted traces:

```bash
daredevil -c mem_data_rw1_200_131176.attack_sbox.config
daredevil -c mem_data_rw1_200_131176.attack_multinv.config
```
