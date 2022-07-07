from hashlib import (
    sha256, md5,
    shake_128, shake_256,
    sha3_256, sha3_512,
    blake2b, blake2s
)


"""New randomized proof-of-work hashing algorithms inspired roughly by
    XMR's RandomX but much simpler and shoddier.
    From https://pastebin.com/xY3B3K8S
"""


def tapehash1(preimage: bytes, code_size: int = 1024) -> bytes:
    """Runs the tapehash 1 algorithm on the preimage and returns a
        32-byte hash. Computational complexity is tuneable via the
        code_size parameter.
    """
    if type(preimage) is not bytes:
        raise TypeError('preimage must be bytes')

    # generate the code and the tape
    code = shake_256(preimage).digest(code_size)
    tape = bytearray(blake2b(preimage).digest())

    # run the program
    for i in range(0, len(code)):
        opcode = code[i] >> 4
        pointer = ((code[i] << 4) % 256) >> 4

        tape = execute_opcode(opcode, pointer, tape)
        tape = execute_opcode(opcode, pointer + 16, tape)
        tape = execute_opcode(opcode, pointer + 32, tape)
        tape = execute_opcode(opcode, pointer + 48, tape)

    return sha256(tape).digest()


def tapehash2(preimage: bytes, tape_size_multiplier: int = 1024*32) -> bytes:
    """Runs the tapehash2 algorithm on the preimage and returns a
        32-byte hash. Memory complexity can be tuned via the
        tape_size_multiplier parameter.
    """
    if type(preimage) is not bytes:
        raise TypeError('preimage must be bytes')
    if type(tape_size_multiplier) is not int:
        raise TypeError('tape_size_multiplier must be an int between 1 and 65,536')
    if tape_size_multiplier <= 0 or tape_size_multiplier > 65_536:
        raise ValueError('tape_size_multiplier must be an int between 1 and 65,536')

    # generate the code and the tape
    code = blake2b(preimage).digest()
    tape = bytearray(shake_256(preimage).digest(tape_size_multiplier * 32))

    # run the program
    for i in range(0, len(code), 2):
        opcode = code[i] >> 4
        pointer = ((code[i] << 4) % 256) >> 4
        double_pointer = int.from_bytes(code[i:i+2], 'big') % tape_size_multiplier

        tape = execute_opcode(opcode, pointer + double_pointer * 32, tape)
        tape = execute_opcode(opcode, pointer + 16 + double_pointer * 32, tape)

    return sha256(tape).digest()


def rotate_tape(tape: bytearray, pointer: int) -> bytes:
    """Rotates the tape so that the pointer-indexed byte is first."""
    if not isinstance(tape, bytearray):
        raise TypeError('tape must be bytearray')
    if not isinstance(pointer, int):
        raise TypeError('pointer must be int')
    if len(tape) < 1:
        raise ValueError('tape must not be empty')
    if pointer < 0 or pointer >= len(tape):
        raise ValueError('pointer must be a valid index of tape')

    new_tape = tape[pointer:]
    new_tape.extend(tape[:pointer])
    return bytes(new_tape)


def execute_opcode(opcode: int, pointer: int, tape: bytearray) -> bytearray:
    """Execute a single opcode."""
    if type(opcode) is not int:
        raise TypeError('opcode must be an int')
    if type(pointer) is not int:
        raise TypeError('pointer must be an int')
    if type(tape) is not bytearray:
        raise TypeError('tape must be bytearray')
    if opcode < 0 or opcode > 15:
        raise ValueError('opcode must be between 0 and 15')
    if pointer < 0 or pointer >= len(tape):
        raise ValueError('pointer must be a valid index of tape')

    operations = {
        0: lambda data: data, # no op
        1: lambda data: (data + 1) % 256,
        2: lambda data: data - 1 if data > 0 else 255,
        3: lambda data: data >> 1,
        4: lambda data: (data << 1) % 256,
        5: lambda data: data ^ 255,
        6: lambda data: (data * 2) % 256,
        7: lambda data: (data ** 2) % 256,
        8: lambda data: (data // 2) % 256,
        9: lambda data: ((data << 4) % 256) | (data >> 4),
        10: lambda data: sha256(data).digest()[data[0] % 32],
        11: lambda data: md5(data).digest()[data[0] % 16],
        12: lambda data: shake_128(data).digest(data[0] + 1)[data[0]],
        13: lambda data: sha3_256(data).digest()[data[0] % 32],
        14: lambda data: sha3_512(data).digest()[data[0] % 64],
        15: lambda data: blake2s(data).digest()[data[0] % 32]
    }

    if opcode < 10:
        tape[pointer] = operations[opcode](tape[pointer])
    else:
        tape[pointer] = operations[opcode](rotate_tape(tape, pointer))
    return tape


def license():
    """Copyleft (c) 2022 k98kurz

        Permission to use, copy, modify, and/or distribute this software
        for any purpose with or without fee is hereby granted, provided
        that the above copyleft notice and this permission notice appear in
        all copies.

        THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
        WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
        WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
        AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
        CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
        OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
        NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
        CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
    """
    return license.__doc__
