from context import tapehash
from time import perf_counter
import unittest


class TestTapeHash(unittest.TestCase):
    """Test suite for tapehash."""

    def test_rotate_tape_rotates_tape(self):
        tape = bytearray(b'hello world')

        assert tapehash.rotate_tape(tape, 0) == tape
        assert tapehash.rotate_tape(tape, 1) == bytearray(b'ello worldh')
        assert tapehash.rotate_tape(tape, 2) == bytearray(b'llo worldhe')
        assert tapehash.rotate_tape(tape, 3) == bytearray(b'lo worldhel')
        assert tapehash.rotate_tape(tape, 4) == bytearray(b'o worldhell')
        assert tapehash.rotate_tape(tape, 5) == bytearray(b' worldhello')
        assert tapehash.rotate_tape(tape, 6) == bytearray(b'worldhello ')
        assert tapehash.rotate_tape(tape, 7) == bytearray(b'orldhello w')
        assert tapehash.rotate_tape(tape, 8) == bytearray(b'rldhello wo')
        assert tapehash.rotate_tape(tape, 9) == bytearray(b'ldhello wor')
        assert tapehash.rotate_tape(tape, 10) == bytearray(b'dhello worl')

    def test_tapehash1_returns_bytes_different_from_preimage(self):
        preimage = b'hello world'
        digest = tapehash.tapehash1(preimage)
        assert type(digest) is bytes
        assert len(digest) == 32
        assert digest != preimage

    def test_tapehash1_result_changes_with_code_size(self):
        preimage = b'hello world'
        digest1 = tapehash.tapehash1(preimage, code_size=128)
        digest2 = tapehash.tapehash1(preimage, code_size=1024)
        assert digest1 != digest2

    def test_tapehash1_execution_time_scales_with_code_size(self):
        preimage = b'hello world'
        start = perf_counter()
        tapehash.tapehash1(preimage, code_size=128)
        diff1 = perf_counter() - start
        start = perf_counter()
        tapehash.tapehash1(preimage, code_size=1024)
        diff2 = perf_counter() - start

        assert diff2 > diff1

    def test_tapehash2_returns_bytes_different_from_preimage(self):
        preimage = b'hello world'
        digest = tapehash.tapehash2(preimage)
        assert type(digest) is bytes
        assert len(digest) == 32
        assert digest != preimage

    def test_tapehash2_result_changes_with_tape_size_multiplier(self):
        preimage = b'hello world'
        digest1 = tapehash.tapehash2(preimage, tape_size_multiplier=128)
        digest2 = tapehash.tapehash2(preimage, tape_size_multiplier=1024)
        assert digest1 != digest2

    def test_tapehash2_execution_time_scales_with_tape_size_multiplier(self):
        preimage = b'hello world'
        start = perf_counter()
        tapehash.tapehash2(preimage, tape_size_multiplier=128)
        diff1 = perf_counter() - start
        start = perf_counter()
        tapehash.tapehash2(preimage, tape_size_multiplier=2048)
        diff2 = perf_counter() - start

        assert diff2 > diff1


if __name__ == '__main__':
    unittest.main()
