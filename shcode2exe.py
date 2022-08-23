#!/usr/bin/env python3
# Modified by d34ddr34m3r on 2022-08-23
# Notes from d34ddr34m3r:
# - use the included compiler and linker binaries
# - run compiler and linker in MacOS via wine
# - added option to set the entry point offset, added delta offset computation in asm code
# - improved the asm code to move the shellcode to the .data section with read-write-execute access

import os
import sys
import shutil
import subprocess
from argparse import ArgumentParser
from pathlib import Path

PLATF_LINUX = 'linux' in sys.platform
PLATF_MACOS = "darwin" in sys.platform

__app_home__ = Path(__file__).parent
__tools_home__ = __app_home__ / "tools"
__nasm_path__ = __tools_home__ / "nasm" / f"nasm{'' if PLATF_LINUX else '.exe'}"
__linker_path__ = __tools_home__ / "linkers" / f"ld{'' if PLATF_LINUX else '.exe'}"


def CheckRequirementsMet(arg_vars):
    if not PLATF_MACOS:
        requirements = ['ld', 'nasm']

        for prog in requirements:
            if shutil.which(prog) is None:
                if prog == 'ld':
                    print("{} is not installed or found. Ensure it is installed (e.g. 'sudo apt install binutils') and in your PATH and try again.".format(prog))
                elif prog == 'nasm':
                    print("{} is not installed or found. Ensure it is installed (e.g 'sudo apt install nasm') and in your PATH and try again.".format(prog))
                else:
                    print("Unmatched or unidentified requirements")
                raise SystemExit(1)
    CompileShellCode(arg_vars)


def ConvertToBin(file_input, filename):
    with open(file_input, 'r', encoding='unicode_escape') as input_file:
        s = input_file.read().replace('\n', '')
        with open(filename + '.bin', 'wb') as gen_file:
            gen_file.write(b'' + bytes(s, encoding='raw_unicode_escape'))
            file_input = filename + '.bin'
    input_file.close()
    gen_file.close()
    return file_input


def CompileShellCode(arguments):
    file_input = arguments['input']

    if arguments['output']:
        filename = os.path.basename(arguments['output']).split('.')[0]
    else:
        filename = f"{file_input}"

    if file_input and not os.path.exists(file_input):
        print('ERROR: File {} does not exist!'.format(file_input))
        raise SystemExit(1)

    if arguments['string']:
        file_input = ConvertToBin(file_input, filename + '-gen')
        if arguments['verbose']:
            print("Converting input file to {}-gen.bin".format(filename))

    ep_offset = arguments['ep_offset']
    asm_file_contents = f"""
    section .text
        global _start
    _start:
        call _shellcode
    section .data "rwx"
    _shellcode:
    """
    if ep_offset:
        asm_file_contents += f"""
        call  _delta 
    _delta:
        pop   eax
        add   eax, 0x{ep_offset + 0x08:08x}
        jmp   eax
"""
    asm_file_contents += f"""
        incbin \"{file_input}\"

    """
    if arguments['verbose']:
        print("Writing assembly instruction to {}.asm".format(filename))
    with open(filename + '.asm', 'w+') as f:
        f.write(asm_file_contents)

    nasm_bin = f"{'wine ' if PLATF_MACOS else ''}{__nasm_path__} -f win{arguments['architecture']} -o {filename}.obj {filename}.asm"
    if arguments['verbose']:
        print("Executing: {}".format(nasm_bin))
    subprocess.check_output(nasm_bin, shell=True)

    ld_bin = f"{'wine ' if PLATF_MACOS else ''}{__linker_path__} -m {'i386pe' if arguments['architecture'] == '32' else 'i386pep'} -o {arguments['output'] if arguments['output'] else filename + '.exe_'} {filename}.obj"
    if arguments['verbose']:
        print("Executing: {}".format(ld_bin))
    subprocess.check_output(ld_bin, shell=True)
    if arguments['verbose']:
        print("Compiled shellcode saved as {}".format(filename))

    if not arguments['keep']:
        if arguments['verbose']:
            print("Attempting to remove {0}.obj, {0}.asm, and {0}-gen.bin (if present)".format(filename))
        os.remove(filename + '.obj')
        os.remove(filename + '.asm')

        if os.path.exists(filename + '-gen.bin'):
            os.remove(filename + '-gen.bin')


def main():
    parser = ArgumentParser(description='Compile shellcode into an exe file from Windows or Linux.')
    parser.add_argument('-o', '--output',
                        help='Set output exe file.')
    parser.add_argument('-s', '--string', action='store_true',
                        help='Set if input file contains shellcode in string format.')
    parser.add_argument('-a', '--architecture', choices=['32', '64'], default='32',
                        help='The windows architecture to use')
    parser.add_argument('-e', '--ep_offset', type=lambda x: int(x, 0), default=0x00,
                        help='Entry point offset, default=0x00')
    parser.add_argument('-k', '--keep', action='store_true',
                        help='Keep files used in compilation')
    parser.add_argument('-V', '--verbose', action='store_true', help='Print actions to stdout')
    parser.add_argument('input',
                        help='The input file containing the shellcode.')
    args = parser.parse_args()

    arg_vars = vars(args)

    CheckRequirementsMet(arg_vars)


if __name__ == '__main__':
    main()

# ~nuninuninu~
