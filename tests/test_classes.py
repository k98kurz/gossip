from context import classes
from nacl.signing import SigningKey, SignedMessage
import unittest


class TestBasicClasses(unittest.TestCase):
    """Test suite for basic classes"""
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        seed = bytes.fromhex('bc66e048abf92e97c35f00607a9260dd8299d91e698253c1090872d7d441df80')
        cls.skey = SigningKey(seed)
        cls.address = bytes(cls.skey.verify_key)

    def test_imports_without_errors(self):
        ...

    # Message tests
    def test_Message_instantiates_with_src_dst_body_ts_and_nonce(self):
        message = classes.Message(b'src', b'dst', b'hello')
        assert hasattr(message, 'src')
        assert type(message.src) is bytes
        assert hasattr(message, 'dst')
        assert type(message.dst) is bytes
        assert hasattr(message, 'body')
        assert type(message.body) is bytes
        assert hasattr(message, 'ts')
        assert type(message.ts) is int
        assert hasattr(message, 'nonce')
        assert type(message.nonce) is int

    def test_Message_instantiates_with_empty_sig_and_metadata(self):
        message = classes.Message(b'src', b'dst', b'hello')
        assert hasattr(message, 'sig')
        assert message.sig is None
        assert hasattr(message, 'metadata')
        assert type(message.metadata) is dict
        assert len(message.metadata.keys()) == 0

    def test_Message_repr_bytes_and_hash_return_valid_types(self):
        message = classes.Message(b'src', b'dst', b'hello')
        assert type(message.__repr__()) is str
        assert type(message.__bytes__()) is bytes
        assert type(message.__hash__()) is int

    def test_Message_get_header_returns_bytes(self):
        message = classes.Message(b'src', b'dst', b'hello')
        assert hasattr(message, 'get_header') and callable(message.get_header)
        assert type(message.get_header()) is bytes

    def test_Message_check_hash_returns_bool(self):
        message = classes.Message(b'src', b'dst', b'hello')
        assert hasattr(message, 'check_hash') and callable(message.check_hash)
        assert type(message.check_hash()) is bool

    def test_Message_pow_changes_nonce_and_makes_check_hash_return_true(self):
        message = classes.Message(b'src', b'dst', b'hello')
        assert hasattr(message, 'pow') and callable(message.pow)

        # ensure the nonce is wrong
        if message.check_hash():
            message.nonce -= 1

        assert not message.check_hash()
        nonce0 = message.nonce
        message.pow()
        assert message.nonce != nonce0
        assert message.check_hash()

    def test_Message_sign_returns_SignedMessage_and_sets_sig_value_to_64_bytes(self):
        message = classes.Message(self.address, self.address, b'hello')
        assert message.sig is None
        assert hasattr(message, 'sign') and callable(message.sign)
        assert type(message.sign(self.skey)) is SignedMessage
        assert type(message.sig) is bytes and len(message.sig) == 64

    def test_Message_verify_returns_bool_and_verifies_signed_message(self):
        message = classes.Message(self.address, self.address, b'hello')
        assert hasattr(message, 'verify') and callable(message.verify)
        assert type(message.verify()) is bool
        assert not message.verify()
        message.sign(self.skey)
        assert message.verify()

    def test_Message_decrypt_raises_TypeError_or_ValueError_for_invalid_skey_arg(self):
        message = classes.Message(self.address, self.address, b'hello')
        message.encrypt()
        with self.assertRaises(TypeError) as e:
            message.decrypt('not a SigningKey')
        assert str(e.exception) == 'skey must be a valid SigningKey'
        with self.assertRaises(ValueError) as e:
            message.decrypt(SigningKey(self.address))
        assert str(e.exception) == 'Must use the skey of the receiver to decrypt.'
        message.decrypt(self.skey)

    def test_Message_encrypt_and_decrypt_change_body_and_return_None(self):
        message = classes.Message(self.address, self.address, b'hello')
        assert hasattr(message, 'encrypt') and callable(message.encrypt)
        assert hasattr(message, 'decrypt') and callable(message.decrypt)

        body0 = message.body
        assert message.encrypt() is None
        assert message.body != body0
        assert message.decrypt(self.skey) is None
        assert message.body == body0

    def test_Message_pack_returns_bytes_and_unpacks_properly(self):
        message = classes.Message(self.address, self.address, b'hello')
        assert hasattr(message, 'pack') and callable(message.pack)
        assert hasattr(classes.Message, 'unpack') and callable(classes.Message.unpack)

        # encrypt and sign
        message.encrypt()
        message.sign(self.skey)

        packed = message.pack()
        assert type(packed) is bytes
        unpacked = classes.Message.unpack(packed)
        assert type(unpacked) is classes.Message
        assert message == unpacked


    # Topic tests


    # Bulletin tests


    # Node tests


    # Neighbor tests


    # Action tests


    # Connection tests


if __name__ == '__main__':
    unittest.main()
