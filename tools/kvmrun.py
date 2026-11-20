"""Create a KVM guest, run it to a HLT, and tear it down.

usage: kvmrun.py [<count>]

Runs inside the test VM with the livepatch applied, so that the patched
KVM paths run: KVM_CREATE_VCPU resets the vCPU (kvm_vcpu_reset()), and
closing the descriptors frees it (svm_vcpu_free() on AMD).  The guest is
one page of real-mode code at guest physical 0: a single HLT.

Constants and layouts are those of include/uapi/linux/kvm.h and
arch/x86/include/uapi/asm/kvm.h (checked against 4.18.0-553.180.1.el8_10).
Prints "kvmrun: runs=<n> hlt=<n>" and exits 0 when every run ended in
KVM_EXIT_HLT; exits 2 when /dev/kvm is absent.
"""
import ctypes
import fcntl
import mmap
import os
import struct
import sys

KVMIO = 0xAE


def _ioc(d, nr, size):
    # asm-generic/ioctl.h: dir<<30 | size<<16 | type<<8 | nr;
    # _IOC_WRITE is 1, _IOC_READ is 2.
    return (d << 30) | (size << 16) | (KVMIO << 8) | nr


KVM_CREATE_VM = _ioc(0, 0x01, 0)
KVM_GET_VCPU_MMAP_SIZE = _ioc(0, 0x04, 0)
KVM_CREATE_VCPU = _ioc(0, 0x41, 0)
KVM_SET_USER_MEMORY_REGION = _ioc(1, 0x46, 32)  # struct kvm_userspace_memory_region
KVM_RUN = _ioc(0, 0x80, 0)
KVM_GET_REGS = _ioc(2, 0x81, 144)  # struct kvm_regs: 18 x __u64
KVM_SET_REGS = _ioc(1, 0x82, 144)
KVM_GET_SREGS = _ioc(2, 0x83, 312)  # struct kvm_sregs
KVM_SET_SREGS = _ioc(1, 0x84, 312)
KVM_EXIT_HLT = 5


def run_once(kvm):
    vm = fcntl.ioctl(kvm, KVM_CREATE_VM, 0)
    # An anonymous mapping, so the memory is page-aligned as
    # KVM_SET_USER_MEMORY_REGION requires.
    mem = mmap.mmap(-1, 0x1000)
    ref = ctypes.c_char.from_buffer(mem)
    vcpu = run = None
    try:
        mem.write(b'\xf4')  # hlt
        region = struct.pack('IIQQQ', 0, 0, 0, 0x1000, ctypes.addressof(ref))
        fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, region)
        vcpu = fcntl.ioctl(vm, KVM_CREATE_VCPU, 0)
        size = fcntl.ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0)
        run = mmap.mmap(vcpu, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)

        # cs is the first struct kvm_segment in kvm_sregs: base at 0,
        # selector at 12.  Real mode stays as the reset left it.
        sregs = bytearray(fcntl.ioctl(vcpu, KVM_GET_SREGS, bytes(312)))
        struct.pack_into('Q', sregs, 0, 0)
        struct.pack_into('H', sregs, 12, 0)
        fcntl.ioctl(vcpu, KVM_SET_SREGS, bytes(sregs))
        # rip and rflags are the last two fields; bit 1 of rflags is
        # reserved and reads as 1.
        regs = bytearray(fcntl.ioctl(vcpu, KVM_GET_REGS, bytes(144)))
        struct.pack_into('QQ', regs, 128, 0, 2)
        fcntl.ioctl(vcpu, KVM_SET_REGS, bytes(regs))

        fcntl.ioctl(vcpu, KVM_RUN, 0)
        # struct kvm_run: two __u8, six bytes of padding, then exit_reason.
        return struct.unpack_from('I', run, 8)[0]
    finally:
        if run is not None:
            run.close()
        if vcpu is not None:
            os.close(vcpu)
        os.close(vm)
        del ref
        mem.close()


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    if not os.path.exists('/dev/kvm'):
        print('kvmrun: no /dev/kvm')
        return 2
    kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    hlt = 0
    reasons = {}
    for _ in range(n):
        r = run_once(kvm)
        reasons[r] = reasons.get(r, 0) + 1
        hlt += r == KVM_EXIT_HLT
    os.close(kvm)
    print('kvmrun: runs=%d hlt=%d exit_reasons=%s' % (n, hlt, reasons))
    return 0 if hlt == n else 1


if __name__ == '__main__':
    sys.exit(main())
