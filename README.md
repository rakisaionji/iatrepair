# IAT Repair

Builds upon Volatility Toolkit's PE dumping capabilities to produce PEs suitable
for re-execution. Requires some fairly mechanical manual interventions in its
current form.

Useful for defeating executable packers that don't have any significant
anti-dumping countermeasures. Examples given are for HyperTech CrackProof (aka
"HtPec") but it may be useful for other packers and protectors.

Notes are fairly rough and ready. Basic familiarity with executable file formats
and reverse engineering tools is assumed.

## Outline

On a Linux system, install QEMU, install Volatility toolkit (both are
installable from Fedora's standard package repositories)

- Run QEMU, enable gdb remote debug with `-s` flag which listens on port 1234
- Suggest running QEMU with 2GB of memory: can run most stuff but isn't big
  enough to be unwieldy. Adjust as needed.
- Run gdb, `remote localhost:1234`
- In gdb, set hyperbreak: `hbreak *0x14022d9e4` (h == hardware here, star is hex
  addr literal i guess?).
  - This freezes the vm whenever RIP equals that value (so, hits virtual addr in
    any process)
  - Address is the target process OEP, obviously this will vary, this is just an
    example.
- In QEMU virtual machine monitor, `pmemsave 0 0x80000000 image.bin`. This saves
  a 2GB _physical_ memory image
- In bash, `volatility --profile=Win8SP1x64 -f image.bin pslist` to list
  processes in the image snapshot
  - `--profile` see:
    https://github.com/volatilityfoundation/volatility/wiki/2.6-Win-Profiles
- In bash,
  `volatility --profile=Win8SP1x64 -f image.bin procdump -D . -m -p 1796`
  - `-D` specifies output directory, this is required
  - `-m` does uh, something. Widens the section sizes based on memory analysis
    heuristics maybe.
  - `-p` is PID, obviously this will vary, 1796 is just an example
- In bash,
  `volatility --profile=Win8SP1x64 -f image.bin impscan -p 1796 --output-file=whatever.txt`
  to analyze IATs, takes a while
- Manually fix up import table:
  - Cut off the two header lines
  - Un-forward NTDLL symbols back to kernel32.dll (otherwise IATs get broken,
    must stay within one DLL until terminating NULL)
  - Look for a big jump in the IAT entry addrs, cut everything off from that
    point on, that's HtPec's internal IATs
- Back up EXE dump, open a copy in CFF explorer, do manual fix ups:
  - Restore OEP
  - Look at IAT virtual addrs, find section hosting them, make it writable (most
    significant Characteristics nibble should be set to C)
  - Delete HtPec sections if you feel like it, cuts off a few MB from the final
    EXE size
- Run iatrepair, yielding a runnable executable

If the exact OEP is not known then (assuming you can make the target process run
for at least a few seconds) manually freeze the VM from gdb by hitting Ctrl-C
and make a dirty dump of the target process for initial analysis.

## QEMU Example

```
#!/bin/sh

exec qemu-system-x86_64 \
        -machine q35 \
        -drive file=/usr/share/edk2/ovmf/OVMF_CODE.fd,if=pflash,format=raw,unit=0,readonly=on \
        -drive file=nvram.bin,if=pflash,format=raw,unit=1 \
        -drive file=/dev/sdb,index=0,media=disk,driver=raw \
        -m 2048 \
        -device qemu-xhci,id=xhci \
        --enable-kvm \
        -s \

```
