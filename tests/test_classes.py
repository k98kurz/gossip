from hashlib import sha256
from queue import SimpleQueue
from context import classes, interfaces
from nacl.signing import SigningKey, SignedMessage, VerifyKey
from unittest.mock import patch
import unittest


class TestBasicClasses(unittest.TestCase):
    """Test suite for basic classes"""
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.seed0 = bytes.fromhex('bc66e048abf92e97c35f00607a9260dd8299d91e698253c1090872d7d441df80')
        cls.seed1 = bytes.fromhex('a7a4b3a2afae8026fb6d523f06f67e5e69ca8e583881ca34574a8e6a9658eaec')
        cls.skey0 = SigningKey(cls.seed0)
        cls.skey1 = SigningKey(cls.seed1)
        cls.address0 = bytes(cls.skey0.verify_key)
        cls.address1 = bytes(cls.skey1.verify_key)

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
        message = classes.Message(self.address0, self.address0, b'hello')
        assert message.sig is None
        assert hasattr(message, 'sign') and callable(message.sign)
        assert type(message.sign(self.skey0)) is SignedMessage
        assert type(message.sig) is bytes and len(message.sig) == 64

    def test_Message_verify_returns_bool_and_verifies_signed_message(self):
        message = classes.Message(self.address0, self.address0, b'hello')
        assert hasattr(message, 'verify') and callable(message.verify)
        assert type(message.verify()) is bool
        assert not message.verify()
        message.sign(self.skey0)
        assert message.verify()

    def test_Message_decrypt_raises_TypeError_or_ValueError_for_invalid_skey_arg(self):
        message = classes.Message(self.address0, self.address0, b'hello')
        message.encrypt()
        with self.assertRaises(TypeError) as e:
            message.decrypt('not a SigningKey')
        assert str(e.exception) == 'skey must be a valid SigningKey'
        with self.assertRaises(ValueError) as e:
            message.decrypt(SigningKey(self.address0))
        assert str(e.exception) == 'Must use the skey of the receiver to decrypt.'
        message.decrypt(self.skey0)

    def test_Message_encrypt_and_decrypt_change_body_and_return_None(self):
        message = classes.Message(self.address0, self.address0, b'hello')
        assert hasattr(message, 'encrypt') and callable(message.encrypt)
        assert hasattr(message, 'decrypt') and callable(message.decrypt)

        body0 = message.body
        assert message.encrypt() is None
        assert message.body != body0
        assert message.decrypt(self.skey0) is None
        assert message.body == body0

    def test_Message_pack_returns_bytes_and_unpacks_properly(self):
        message = classes.Message(self.address0, self.address0, b'hello')
        assert hasattr(message, 'pack') and callable(message.pack)
        assert hasattr(classes.Message, 'unpack') and callable(classes.Message.unpack)

        # encrypt and sign
        message.encrypt()
        message.sign(self.skey0)

        packed = message.pack()
        assert type(packed) is bytes
        unpacked = classes.Message.unpack(packed)
        assert type(unpacked) is classes.Message
        assert message == unpacked


    # Topic tests
    def test_Topic_instantiates_with_id_and_descriptor(self):
        topic = classes.Topic(b'abc', b'letters')
        assert hasattr(topic, 'id') and type(topic.id) is bytes
        assert hasattr(topic, 'descriptor') and type(topic.descriptor) is bytes

    def test_Topic_from_descriptor_sets_id_to_shake256_of_descriptor(self):
        descriptor = b'node beacon channel'
        digest = sha256(descriptor).digest()
        topic = classes.Topic.from_descriptor(descriptor)
        assert topic.id == digest

    def test_Topic_hash_bytes_repr_return_proper_types(self):
        topic = classes.Topic.from_descriptor(b'node beacon channel')
        assert hasattr(topic, '__hash__') and callable(topic.__hash__)
        assert type(topic.__hash__()) is int
        assert hasattr(topic, '__bytes__') and callable(topic.__bytes__)
        assert type(topic.__bytes__()) is bytes
        assert hasattr(topic, '__repr__') and callable(topic.__repr__)
        assert type(topic.__repr__()) is str


    # Bulletin tests
    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_instantiates_with_topic_and_content(self):
        topic = interfaces.AbstractTopic(b'123', b'descriptor')
        bulletin = classes.Bulletin(topic, b'hello world, this is ' + self.address0)
        assert hasattr(bulletin, 'topic') and isinstance(bulletin.topic, interfaces.AbstractTopic)
        assert hasattr(bulletin, 'content') and type(bulletin.content) is bytes

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_bytes_hash_methods_return_proper_types(self):
        topic = interfaces.AbstractTopic(b'123', b'descriptor')
        bulletin = classes.Bulletin(topic, b'hello world, this is ' + self.address0)
        assert hasattr(bulletin, '__bytes__') and callable(bulletin.__bytes__)
        assert type(bulletin.__bytes__()) is bytes
        assert hasattr(bulletin, '__hash__') and callable(bulletin.__hash__)
        assert type(bulletin.__hash__()) is int

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_pack_and_unpack_return_correct_types_and_values(self):
        descriptor = b'node beacon channel'
        topic_id = sha256(descriptor).digest()
        topic = interfaces.AbstractTopic(topic_id)
        bulletin = classes.Bulletin(topic, b'hello world, this is ' + self.address0)
        assert hasattr(bulletin, 'pack') and callable(bulletin.pack)
        assert hasattr(classes.Bulletin, 'unpack') and callable(classes.Bulletin.unpack)

        packed = bulletin.pack()
        assert type(packed) is bytes

        unpacked = classes.Bulletin.unpack(packed)
        assert type(unpacked) is classes.Bulletin
        assert unpacked == bulletin


    # Node tests
    def test_Node_instantiates_with_specified_properties(self):
        node = classes.Node(self.address0)
        assert hasattr(node, 'address') and type(node.address) is bytes
        assert hasattr(node, 'msgs_seen') and type(node.msgs_seen) is set
        assert hasattr(node, 'bulletins') and type(node.bulletins) is set
        assert hasattr(node, 'topics_followed') and type(node.topics_followed) is set
        assert hasattr(node, 'connections') and type(node.connections) is set
        assert hasattr(node, 'data') and type(node.data) is dict
        assert hasattr(node, '_seed') and node._seed is None
        assert hasattr(node, '_skey') and node._skey is None
        assert hasattr(node, '_vkey') and type(node._vkey) is VerifyKey
        assert hasattr(node, '_inbound') and type(node._inbound) is SimpleQueue
        assert hasattr(node, '_outbound') and type(node._outbound) is SimpleQueue
        assert hasattr(node, '_actions') and type(node._actions) is SimpleQueue
        assert hasattr(node, '_message_sender') and node._message_sender is None
        assert hasattr(node, '_message_handler') and node._message_handler is None
        assert hasattr(node, '_action_handler') and node._action_handler is None

    def test_Node_from_seed_instantiates_with_specified_properties(self):
        node = classes.Node.from_seed(self.seed0)
        assert hasattr(node, 'address') and type(node.address) is bytes
        assert hasattr(node, 'msgs_seen') and type(node.msgs_seen) is set
        assert hasattr(node, 'bulletins') and type(node.bulletins) is set
        assert hasattr(node, 'topics_followed') and type(node.topics_followed) is set
        assert hasattr(node, 'connections') and type(node.connections) is set
        assert hasattr(node, 'data') and type(node.data) is dict
        assert hasattr(node, '_seed') and type(node._seed) is bytes
        assert hasattr(node, '_skey') and type(node._skey) is SigningKey
        assert hasattr(node, '_vkey') and type(node._vkey) is VerifyKey
        assert hasattr(node, '_inbound') and type(node._inbound) is SimpleQueue
        assert hasattr(node, '_outbound') and type(node._outbound) is SimpleQueue
        assert hasattr(node, '_actions') and type(node._actions) is SimpleQueue
        assert hasattr(node, '_message_sender') and node._message_sender is None
        assert hasattr(node, '_message_handler') and node._message_handler is None
        assert hasattr(node, '_action_handler') and node._action_handler is None

    def test_Nodes_can_encrypt_and_decrypt_Messages(self):
        # create the nodes
        node0 = classes.Node.from_seed(self.seed0)
        node1 = classes.Node.from_seed(self.seed1)

        # create a message
        node0.send_message(node1.address, b'hello')
        assert node0._outbound.qsize() == 1
        message = node0._outbound.get()
        assert isinstance(message, interfaces.AbstractMessage)
        assert message.body != b'hello'

        # deliver the message
        node1.receive_message(message)
        assert node1._inbound.qsize() == 1
        message = node1._inbound.get()
        assert message.body == b'hello'


    # Neighbor tests


    # Action tests


    # Connection tests


if __name__ == '__main__':
    unittest.main()
