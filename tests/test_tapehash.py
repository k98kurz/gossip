from context import tapehash
from time import perf_counter
import unittest


class TestTapeHash(unittest.TestCase):
    """Test suite for tapehash."""

    def test_rotate_tape_raises_TypeError_or_ValueError_on_invalid_args(self):
        with self.assertRaises(TypeError) as e:
            tapehash.rotate_tape(b'not a byte array', 2)
        assert str(e.exception) == 'tape must be bytearray'

        with self.assertRaises(TypeError) as e:
            tapehash.rotate_tape(bytearray(b'a byte array'), 'not an int')
        assert str(e.exception) == 'pointer must be int'

        with self.assertRaises(ValueError) as e:
            tapehash.rotate_tape(bytearray(b''), 0)
        assert str(e.exception) == 'tape must not be empty'

        with self.assertRaises(ValueError) as e:
            tapehash.rotate_tape(bytearray(b'1'), 2)
        assert str(e.exception) == 'pointer must be a valid index of tape'

    def test_rotate_tape_rotates_tape(self):
        tape = bytearray(b'hello world')

        assert tapehash.rotate_tape(tape, 0) == tape
        assert tapehash.rotate_tape(tape, 1) == b'ello worldh'
        assert tapehash.rotate_tape(tape, 2) == b'llo worldhe'
        assert tapehash.rotate_tape(tape, 3) == b'lo worldhel'
        assert tapehash.rotate_tape(tape, 4) == b'o worldhell'
        assert tapehash.rotate_tape(tape, 5) == b' worldhello'
        assert tapehash.rotate_tape(tape, 6) == b'worldhello '
        assert tapehash.rotate_tape(tape, 7) == b'orldhello w'
        assert tapehash.rotate_tape(tape, 8) == b'rldhello wo'
        assert tapehash.rotate_tape(tape, 9) == b'ldhello wor'
        assert tapehash.rotate_tape(tape, 10) == b'dhello worl'

    def test_execute_opcode_raises_TypeError_or_ValueError_on_invalid_args(self):
        with self.assertRaises(TypeError) as e:
            tapehash.execute_opcode('not an int', 2, bytearray(b'asd'))
        assert str(e.exception) == 'opcode must be an int'

        with self.assertRaises(TypeError) as e:
            tapehash.execute_opcode(0, 'not an int', bytearray(b'sds'))
        assert str(e.exception) == 'pointer must be an int'

        with self.assertRaises(TypeError) as e:
            tapehash.execute_opcode(0, 0, 'not a bytearray')
        assert str(e.exception) == 'tape must be bytearray'

        with self.assertRaises(ValueError) as e:
            tapehash.execute_opcode(-1, 0, bytearray(b'asd'))
        assert str(e.exception) == 'opcode must be between 0 and 15'

        with self.assertRaises(ValueError) as e:
            tapehash.execute_opcode(16, 0, bytearray(b'asd'))
        assert str(e.exception) == 'opcode must be between 0 and 15'

        with self.assertRaises(ValueError) as e:
            tapehash.execute_opcode(0, -1, bytearray(b'asd'))
        assert str(e.exception) == 'pointer must be a valid index of tape'

        with self.assertRaises(ValueError) as e:
            tapehash.execute_opcode(0, 4, bytearray(b'asd'))
        assert str(e.exception) == 'pointer must be a valid index of tape'

    def test_execute_opcode_output_for_each_opcode(self):
        tape = lambda: bytearray(b'\x00\x01\x02')

        new_tape = tapehash.execute_opcode(0, 0, tape())
        assert new_tape == tape()

        new_tape = tapehash.execute_opcode(1, 0, tape())
        assert new_tape[0] == 1

        new_tape = tapehash.execute_opcode(2, 0, tape())
        assert new_tape[0] == 255

        new_tape = tapehash.execute_opcode(3, 1, tape())
        assert new_tape[1] == 0

        new_tape = tapehash.execute_opcode(4, 1, tape())
        assert new_tape[1] == 1 << 1

        new_tape = tapehash.execute_opcode(5, 1, tape())
        assert new_tape[1] == 1 ^ 255

        new_tape = tapehash.execute_opcode(6, 1, tape())
        assert new_tape[1] == 2

        new_tape = tapehash.execute_opcode(7, 2, tape())
        assert new_tape[2] == 4

        new_tape = tapehash.execute_opcode(8, 2, tape())
        assert new_tape[2] == 1

        new_tape = tapehash.execute_opcode(9, 2, tape())
        assert new_tape[2] == 32

        new_tape = tapehash.execute_opcode(10, 0, tape())
        assert new_tape[0] == 174

        new_tape = tapehash.execute_opcode(11, 0, tape())
        assert new_tape[0] == 185

        new_tape = tapehash.execute_opcode(12, 0, tape())
        assert new_tape[0] == 32

        new_tape = tapehash.execute_opcode(13, 0, tape())
        assert new_tape[0] == 17

        new_tape = tapehash.execute_opcode(14, 0, tape())
        assert new_tape[0] == 18

        new_tape = tapehash.execute_opcode(15, 0, tape())
        assert new_tape[0] == 232

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
