from context import misc
import unittest


class TestMisc(unittest.TestCase):
    """Test suite for miscellaneous functions and global values."""
    def test_ENABLE_DEBUG_is_bool(self):
        assert hasattr(misc, 'ENABLE_DEBUG')
        assert type(misc.ENABLE_DEBUG) is bool

    def test_DISPLAY_SHORT_ADDRESSES_is_bool(self):
        assert hasattr(misc, 'DISPLAY_SHORT_ADDRESSES')
        assert type(misc.DISPLAY_SHORT_ADDRESSES) is bool

    def test_CONTENT_TTL_is_int(self):
        assert hasattr(misc, 'CONTENT_TTL')
        assert type(misc.CONTENT_TTL) is int

    def test_MESSAGE_TTL_is_int(self):
        assert hasattr(misc, 'MESSAGE_TTL')
        assert type(misc.MESSAGE_TTL) is int

    def test_DEBUG_HANDLERS_is_list(self):
        assert hasattr(misc, 'DEBUG_HANDLERS')
        assert type(misc.DEBUG_HANDLERS) is list

    def test_DEBUG_HANLDERS_contains_print(self):
        assert print in misc.DEBUG_HANDLERS

    def test_MESSAGE_DIFFICULTY_is_int(self):
        assert hasattr(misc, 'MESSAGE_DIFFICULTY')
        assert type(misc.MESSAGE_DIFFICULTY) is int

    def test_BULLETIN_DIFFICULTY_is_int(self):
        assert hasattr(misc, 'BULLETIN_DIFFICULTY')
        assert type(misc.BULLETIN_DIFFICULTY) is int

    def test_TAPEHASH_CODE_SIZE_is_int(self):
        assert hasattr(misc, 'TAPEHASH_CODE_SIZE')
        assert type(misc.TAPEHASH_CODE_SIZE) is int

    def test_format_address_raises_TypeError_for_non_byte_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.format_address(123)
        assert str(e.exception) == 'address must be bytes'

    def test_toggle_short_address_changes_DISPLAY_SHORT_ADDRESSES(self):
        before = misc.DISPLAY_SHORT_ADDRESSES
        misc.toggle_short_address()
        after = misc.DISPLAY_SHORT_ADDRESSES
        assert before is not after

    def test_debug_raises_TypeError_for_non_str_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.debug(123)
        assert str(e.exception) == 'msg must be str'

    def test_register_debug_handler_raises_TypeError_for_non_callable_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.register_debug_handler(123)
        assert str(e.exception) == 'Can only register callables as debug handlers.'

    def test_deregister_debug_handler_raises_TypeError_for_non_callable_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.deregister_debug_handler(123)
        assert str(e.exception) == 'Can only deregister callables as debug handlers.'

    def test_toggle_debug_returns_bool(self):
        assert type(misc.toggle_debug()) is bool

    def test_toggle_short_address_returns_bool(self):
        assert type(misc.toggle_short_address()) is bool

    def test_debug_end_to_end(self):
        flag = False
        msg = 'debug e2e test'
        def debug(msg: str):
            nonlocal flag
            flag = not flag

        # enable debug
        if not misc.ENABLE_DEBUG:
            misc.toggle_debug()

        # deregister print from debug handlers
        misc.deregister_debug_handler(print)

        # register custom handler and ensure it gets called
        misc.register_debug_handler(debug)
        misc.debug(msg)
        assert flag == True

        # disable debug and ensure custom handler does not get called
        misc.toggle_debug()
        misc.debug(msg)
        assert flag == True

        # re-enable debug and make sure custom handler gets called
        misc.toggle_debug()
        misc.debug(msg)
        assert flag == False

        # deregister handler and make sure it does not get called
        misc.deregister_debug_handler(debug)
        misc.debug(msg)
        assert flag == False

        # reregister print as debug handler
        misc.register_debug_handler(print)

    def test_set_difficulty_raises_TypeError_for_non_int_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.set_difficulty('abc')
        assert str(e.exception) == 'difficulty must be an int'

    def test_set_difficulty_sets_BULLETIN_DIFFICULTY_to_int_arg(self):
        original_diff = misc.BULLETIN_DIFFICULTY
        misc.set_difficulty(original_diff + 1)
        assert original_diff != misc.BULLETIN_DIFFICULTY
        assert misc.BULLETIN_DIFFICULTY == original_diff + 1

        # reset
        misc.set_difficulty(original_diff)

    def test_calculate_difficulty_raises_TypeError_for_non_bytes_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.calculate_difficulty(1234)
        assert str(e.exception) == 'digest must be bytes'

    def test_calculate_difficulty_produces_valid_output(self):
        assert misc.calculate_difficulty(b'\x0f') == 4
        assert misc.calculate_difficulty(b'\x07') == 5
        assert misc.calculate_difficulty(b'\x00') == 8

    def test_check_difficulty_raises_TypeError_for_non_bytes_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.check_difficulty(1234, 1)
        assert str(e.exception) == 'digest must be bytes'

    def test_check_difficulty_raises_TypeError_for_non_bytes_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.check_bulletin_difficulty(1234)
        assert str(e.exception) == 'digest must be bytes'

    def test_check_bulletin_difficulty_raises_TypeError_for_non_bytes_arg(self):
        with self.assertRaises(TypeError) as e:
            misc.check_bulletin_difficulty(1234)
        assert str(e.exception) == 'digest must be bytes'

    def test_check_bulletin_difficulty_end_to_end(self):
        misc.set_difficulty(8)
        assert misc.check_bulletin_difficulty(b'\x00')
        assert not misc.check_bulletin_difficulty(b'\x01')

        misc.set_difficulty(5)
        assert misc.check_bulletin_difficulty(b'\x07')
        assert not misc.check_bulletin_difficulty(b'\x08')


if __name__ == '__main__':
    unittest.main()
