from context import tapehash
from time import time
import unittest


class TestTapeHash(unittest.TestCase):
    """Test suite for tapehash."""

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
        start = time()
        tapehash.tapehash1(preimage, code_size=128)
        diff1 = time() - start
        start = time()
        tapehash.tapehash1(preimage, code_size=1024)
        diff2 = time() - start

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
        start = time()
        tapehash.tapehash2(preimage, tape_size_multiplier=128)
        diff1 = time() - start
        start = time()
        tapehash.tapehash2(preimage, tape_size_multiplier=1024)
        diff2 = time() - start

        assert diff2 > diff1


if __name__ == '__main__':
    unittest.main()
