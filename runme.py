#!/bin/env python3
import subprocess

LINE_SIZE = 16
NUM_BYTES = 64


def print_wait_run(cmds):
    cmd_list = isinstance(cmds, list)
    if not cmd_list:
        cmds = [cmds]
    outputs = []
    for cmd in cmds:
        print()
        input(cmd)
        proc = subprocess.run(cmd, shell=True, executable="/bin/bash", stdout=subprocess.PIPE)
        if (proc.returncode != 0):
            raise Exception("Failed with code: ", proc.returncode)
        output = proc.stdout.decode()
        print(output)
        outputs.append(output)
    
    return outputs if cmd_list else outputs[0]


def validate_output(program_output_cmd, expected_output_cmd):
    proc = subprocess.run(program_output_cmd, shell=True, stdout=subprocess.PIPE)
    output = proc.stdout
    proc = subprocess.run(expected_output_cmd, shell=True,
                          stdout=subprocess.PIPE)
    expected_output = proc.stdout

    # Decode hex bytes to their decimal values
    output = [
        int(byte, 16)
        # Split lines, ignore the first lines with other info
        for line in output.decode().split('\n')[3:]
        for byte in line.split(' ')
        if byte  # Ignore empty bytes
    ]

    expected_output = [
        int(byte, 16)
        for line in expected_output.decode().split('\n')
        for byte in line.split(' ')
        if byte
    ]

    return all([lhs == rhs for lhs, rhs in zip(output, expected_output)])


def compile():
    input("Press enter to advance\n")

    print(f"""Let's generate {NUM_BYTES} bytes of pseudorandom data.

    dd copies data from block devices.
    if is the input device
    /dev/urandom is a kernel device that returns pseudorandom data, seeded from /dev/random
    of is the output device/file
    bs is the block size — 1 byte
    count is how many blocks we want to copy""")
    print_wait_run(
        f"dd if=/dev/urandom of=random_data.bin bs=1 count={NUM_BYTES}")

    print(f"""Let's take a look at them.

Print {LINE_SIZE} groups of 1 byte ({LINE_SIZE}/1), 
formatted (%) as 0-padded (0) 2 characters wide (2) hexadecimal (x) (%02x), 
followed by a newline (\\n).""")
    expected_output_cmd = "hexdump -e '" + \
        f'{LINE_SIZE}/1'+' "%02x " "\\n" '+"' random_data.bin"
    print_wait_run(expected_output_cmd)

    print(f"""Let's store how many bytes we print per line ({LINE_SIZE}, hexadecimal: 0x{LINE_SIZE:x}), 
so the C++ program can format it properly.""")
    print_wait_run(f"echo -ne \"\\x{LINE_SIZE:x}\" > format_data.bin")

    print("""Let's make an object file out of that that we can link.

    ld links object files.
    -b binary tells the linker the input format is binary data
    -r means relocatable — tells the linker that the output is not an executable,
    but an object file, that will be linked in another invocation, in other words,
    the output will be \"relocated\" to the final binary.
    -o is the name of the output file.""")
    print_wait_run(
        ["ld -b binary -r -o random_data.o random_data.bin",
         "ld -b binary -r -o format_data.o format_data.bin"])

    print("""Let's see what the symbols are named.

    -C means \"demangle\" — symbols have some garbage around them
    to prevent conflicts when two functions have the same name in different classes.""")
    print_wait_run(
        ["nm -C random_data.o",
         "nm -C format_data.o"])

    print("""Now run the compiler. the -c flag means to skip linking for now.
This will output a compiled object file named linker_example.o.""")
    print_wait_run("g++ -c linker_example.cpp")

    print("""Let's check if our symbols have been defined.
    
Only look for ours, cause the binary will name a lot of symbols.
Those are the standard library functions we have #include-d """)

    print_wait_run("nm -C linker_example.o | grep _binary")

    print("""There they are. \"U\" means undefined, as expected. 
They're waiting for the linker to define them.

Let's link; let g++ call ld for us, it will set up paths for the standard library functions.""")
    print_wait_run(
        "g++ random_data.o format_data.o linker_example.o -o linker_example")

    print("Now let's run the program")
    program_output_cmd = f"./linker_example {NUM_BYTES}"
    print_wait_run(program_output_cmd)

    print("Do they match? Let's look at the file we linked again:")
    print_wait_run(expected_output_cmd)

    matches = validate_output(program_output_cmd, expected_output_cmd)
    if matches:
        print("(I think they do… ☺)")
    else:
        print("Mmm… something looks off…")
        raise Exception("Output doesn't match!")
    print()

def disassemble():
    print("""Now let's disassemble the executable we got. 
First, let's see where the symbols are located""")
    res = print_wait_run("nm -C linker_example | grep \"_binary.*_start\"")
    lines = [ line for line in res.split("\n") if line ]
    for line in lines:
        section = line.split()[1]
        if section != "D":
            raise Exception(f"Found symbol in invalid section: {section}")
    print("'D' here means that the symbols are in the .data section.\n")
    
    print("""Let's get the offset of the .data section in the ELF executable.
    
objdump is the disassembler.
-h dumps the program header.

We care about the "file offset" field, which is the location of the section in the file,
and the VMA (Virtual Memory Address) field. 

When programs are run they are copied into memory within their virtual address space.

They think they're the only thing existing in memory, and that memory starts from address 0.
This is of course not how memory works, but the kernel (Linux) hides what's actually happening.
Every time they query an address, this address is assumed within the program's virtual address space.
The kernel fetches the actual value from the actual memory address (physical memory address).
""")
    print_wait_run('objdump -h linker_example')

    res = subprocess.run('objdump -h linker_example | grep "\.data "',shell=True, stdout=subprocess.PIPE).stdout.decode()
    cols = res.split()
    data_section_mem_offset = int(cols[3],16)
    data_section_file_offset = int(cols[5],16)

    input()
    print(f"From this line:")
    print(res)
    print(f"""The data section offset in the file in this case is 0x{data_section_file_offset:x}, \
while the offset in memory is 0x{data_section_mem_offset:x}
""")

    print("""Let's see how the data section looks like.
    
-t dumps symbol information
-j .data specifies to only look at the .data section """)
    res = print_wait_run("objdump -t -j .data linker_example | grep \"_binary.*_start\"")
    lines = [ line for line in res.split("\n") if line ]
    symbol_offsets = dict()
    for line in lines:
        cols = line.split(' ')
        symbol = cols[-1]
        vma = int(cols[0],16)
        symbol_offsets[symbol] = vma-data_section_mem_offset
        print(f"{symbol} is at memory address 0x{vma:x}, so at offset 0x{symbol_offsets[symbol]:x} in the .data section")
    print()

    num_hexdump_lines = NUM_BYTES//LINE_SIZE + 1
    print("""Let's look at the file.
    
Add the offset (_a) in hexadecimal format (x) at the beginning of each line.
This is printed by hexdump if called with no arguments.
However that would print 2-byte sequences, whereas we want single bytes.

Then we grep enough lines after the address we're looking for to check the output.""")

    def grep_offset_cmd(symbol,n_lines): 
        off = symbol_offsets[symbol]+data_section_file_offset
        off = off - (off % LINE_SIZE) # Align offset down to line size
        cmd = "hexdump -e '" + \
        f'"%05_ax: " {LINE_SIZE}/1'+' "%02x " "\\n" '+"' linker_example" + \
        f" | grep -A{n_lines-1} {off:x}:"
        return off,cmd
    symbol = "_binary_random_data_bin_start"
    off,cmd = grep_offset_cmd(symbol,num_hexdump_lines)
    print(f"Look for {symbol} at 0x{off:x}")
    res = print_wait_run(cmd)
    lines = [ line for line in res.split('\n') if line ]
    found_random_data = [ int(b,16) for line in lines for b in line.split(' ')[1:] if b ][:NUM_BYTES]

    symbol = "_binary_format_data_bin_start"
    off,cmd = grep_offset_cmd(symbol,1)
    print(f"Look for {symbol} at 0x{off:x}")
    ret = print_wait_run(cmd)
    found_line_size = int(ret.split(' ')[1],16)

    print("Do these check out?")
    if (found_line_size!=LINE_SIZE):
        raise Exception("Executable seems to report LINE_SIZE={line_size_found} instead of {LINE_SIZE}!")
    expected_random_data = []
    with open("random_data.bin",'rb') as f:
        while byte := f.read(1):
            expected_random_data.append(int.from_bytes(byte, "little"))
    if not all( lhs == rhs for lhs,rhs in zip(found_random_data,expected_random_data)):
        raise Exception("Executable _binary_random_data_bin_start doesn't match random_data.bin")
    print("They look good to me ☺")
    

if __name__ == "__main__":
    compile()
    disassemble()