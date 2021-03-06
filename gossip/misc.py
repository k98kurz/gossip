# global config and toggle/utility functions
from typing import Callable


ENABLE_DEBUG = True
DISPLAY_SHORT_ADDRESSES = True
CONTENT_TTL = 3600
MESSAGE_TTL = 300
DEBUG_HANDLERS = [print]
MESSAGE_DIFFICULTY = 1
BULLETIN_DIFFICULTY = 7
TAPEHASH_CODE_SIZE = 64


def format_address(address: bytes) -> str:
    if type(address) is not bytes:
        raise TypeError('address must be bytes')

    global DISPLAY_SHORT_ADDRESSES
    return address.hex()[:8] if DISPLAY_SHORT_ADDRESSES else address.hex()

def toggle_short_address() -> bool:
    global DISPLAY_SHORT_ADDRESSES
    DISPLAY_SHORT_ADDRESSES = not DISPLAY_SHORT_ADDRESSES
    return DISPLAY_SHORT_ADDRESSES

def debug(msg: str):
    """Pass debug messages to all debug message handlers."""
    if type(msg) is not str:
        raise TypeError('msg must be str')

    global ENABLE_DEBUG, DEBUG_HANDLERS
    if ENABLE_DEBUG:
        for d in DEBUG_HANDLERS:
            d(msg)

def register_debug_handler(c: Callable) -> None:
    """Register a new function for handling debug messages."""
    if not callable(c):
        raise TypeError('Can only register callables as debug handlers.')
    global DEBUG_HANDLERS
    if c not in DEBUG_HANDLERS:
        DEBUG_HANDLERS.append(c)

def deregister_debug_handler(c: Callable) -> None:
    """deregister a function from handling debug messages."""
    if not callable(c):
        raise TypeError('Can only deregister callables as debug handlers.')
    global DEBUG_HANDLERS
    if c in DEBUG_HANDLERS:
        DEBUG_HANDLERS.remove(c)

def toggle_debug() -> bool:
    global ENABLE_DEBUG
    ENABLE_DEBUG = not ENABLE_DEBUG
    return ENABLE_DEBUG

def set_difficulty(difficulty: int) -> None:
    if type(difficulty) is not int:
        raise TypeError('difficulty must be an int')
    global BULLETIN_DIFFICULTY
    BULLETIN_DIFFICULTY = difficulty

def calculate_difficulty(digest: bytes, bigendian: bool = True) -> int:
    """Calculate the difficulty (number of preceding null bits)."""
    if type(digest) is not bytes:
        raise TypeError('digest must be bytes')

    # prepare variables
    number = int.from_bytes(digest, byteorder = 'big' if bigendian else 'little')
    length = len(digest)
    trailing_bits = 0

    # shift off bits until a null result is achieved
    while number != 0 and trailing_bits < length * 8:
        number = number >> 1
        trailing_bits += 1

    # difficulty achieved is the preceeding null bits
    return length * 8 - trailing_bits

def check_difficulty(digest: bytes, target: int, bigendian: bool = True) -> bool:
    """Checks if a digest meets the target difficulty threshold (preceeding null bits)."""
    if type(digest) is not bytes:
        raise TypeError('digest must be bytes')

    # prepare variables
    number = int.from_bytes(digest, byteorder='big' if bigendian else 'little')
    length = len(digest)

    # raise exception if difficulty is impossible to achieve
    if target > length * 8:
        raise ValueError('Bit length of input must be less than target difficulty')

    # shift off all but {BULLETIN_DIFFICULTY} preceding bits
    preceding_bits = number >> (length * 8 - target)

    # it meets the difficulty if preceding bits are 0
    return preceding_bits == 0

def check_bulletin_difficulty(digest: bytes, bigendian: bool = True) -> bool:
    """Checks if a digest meets the BULLETIN_DIFFICULTY threshold (preceeding null bits)."""
    global BULLETIN_DIFFICULTY
    return check_difficulty(digest, BULLETIN_DIFFICULTY, bigendian)
