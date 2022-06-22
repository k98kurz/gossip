from hashlib import sha256
from queue import SimpleQueue
from context import classes, interfaces, misc
from nacl.signing import SigningKey, VerifyKey
from unittest.mock import patch
import unittest


class TestBasicClasses(unittest.TestCase):
    """Test suite for basic classes"""
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.seed0 = bytes.fromhex('bc66e048abf92e97c35f00607a9260dd8299d91e698253c1090872d7d441df80')
        cls.seed1 = bytes.fromhex('a7a4b3a2afae8026fb6d523f06f67e5e69ca8e583881ca34574a8e6a9658eaec')
        cls.seed2 = bytes.fromhex('a5f496e55953105c5f80939f7a7794edcfd89997e801b6365effd35af1150b02')
        cls.skey0 = SigningKey(cls.seed0)
        cls.skey1 = SigningKey(cls.seed1)
        cls.skey2 = SigningKey(cls.seed2)
        cls.address0 = bytes(cls.skey0.verify_key)
        cls.address1 = bytes(cls.skey1.verify_key)
        cls.address2 = bytes(cls.skey2.verify_key)

    def test_imports_without_errors(self):
        assert True


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

    def test_Message_hashcash_changes_nonce_and_makes_check_hash_return_true(self):
        message = classes.Message(b'src', b'dst', b'hello')
        assert hasattr(message, 'hashcash') and callable(message.hashcash)

        # ensure the nonce is wrong
        while message.check_hash():
            message.nonce -= 1
            if message.nonce < 0:
                message.nonce = 2**16-1

        assert not message.check_hash()
        nonce0 = message.nonce
        assert isinstance(message.hashcash(), interfaces.AbstractMessage)
        assert message.nonce != nonce0
        assert message.check_hash()

    def test_Message_sign_returns_AbstractMessage_and_sets_sig_value_to_64_bytes(self):
        message = classes.Message(self.address0, self.address0, b'hello')
        assert message.sig is None
        assert hasattr(message, 'sign') and callable(message.sign)
        assert isinstance(message.sign(self.skey0), interfaces.AbstractMessage)
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
        assert isinstance(message.decrypt(self.skey0), interfaces.AbstractMessage)

    def test_Message_encrypt_and_decrypt_change_body_and_return_Message(self):
        message = classes.Message(self.address0, self.address0, b'hello')
        assert hasattr(message, 'encrypt') and callable(message.encrypt)
        assert hasattr(message, 'decrypt') and callable(message.decrypt)

        body0 = message.body
        assert isinstance(message.encrypt(), interfaces.AbstractMessage)
        assert message.body != body0
        assert isinstance(message.decrypt(self.skey0), interfaces.AbstractMessage)
        assert message.body == body0

    def test_Message_pack_returns_bytes_and_unpacks_properly(self):
        message = classes.Message(self.address0, self.address0, b'hello')
        assert hasattr(message, 'pack') and callable(message.pack)
        assert hasattr(classes.Message, 'unpack') and callable(classes.Message.unpack)

        # encrypt and sign
        message.encrypt().sign(self.skey0)

        packed = message.pack()
        assert type(packed) is bytes
        unpacked = classes.Message.unpack(packed)
        assert type(unpacked) is classes.Message
        assert message == unpacked


    # Content tests
    def test_Content_instantiates_with_and_bytes_id_and_content(self):
        content = classes.Content(b'123', b'hello world')
        assert hasattr(content, 'id') and type(content.id) is bytes
        assert hasattr(content, 'content') and type(content.content) is bytes

    def test_Content_from_content_raises_TypeError_for_non_bytes_arg(self):
        with self.assertRaises(TypeError) as e:
            classes.Content.from_content('not bytes')
        assert str(e.exception) == 'content must be bytes'

    def test_Content_from_content_sets_id_to_hash_of_content(self):
        content = classes.Content.from_content(b'hello world')
        assert content.id == sha256(b'hello world').digest()

    def test_Content_pack_returns_bytes_and_unpacks_properly(self):
        content = classes.Content.from_content(b'hello world')
        packed = content.pack()
        assert type(packed) is bytes
        unpacked = classes.Content.unpack(packed)
        assert isinstance(unpacked, classes.Content)
        assert unpacked == content


    # Topic tests
    def test_Topic_instantiates_with_id_and_descriptor(self):
        topic = classes.Topic(b'abc', b'letters')
        assert hasattr(topic, 'id') and type(topic.id) is bytes
        assert hasattr(topic, 'descriptor') and type(topic.descriptor) is bytes

    def test_Topic_from_descriptor_raises_TypeError_for_non_bytes_arg(self):
        with self.assertRaises(TypeError) as e:
            classes.Topic.from_descriptor('not bytes')
        assert str(e.exception) == 'descriptor must be bytes'

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
    def test_Bulletin_init_raises_TypeError_for_non_AbstractTopic_arg(self):
        with self.assertRaises(TypeError) as e:
            classes.Bulletin('not a topic', b'content')
        assert str(e.exception) == 'topic must implement AbstractTopic'

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_init_raises_TypeError_for_non_AbstractContent_content(self):
        with self.assertRaises(TypeError) as e:
            classes.Bulletin(interfaces.AbstractTopic(b'hello world'), 'not AbstractContent')
        assert str(e.exception) == 'content must implement AbstractContent'

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_instantiates_with_topic_content_ts_and_nonce(self):
        topic = interfaces.AbstractTopic(b'123', b'descriptor')
        content = classes.Content.from_content(b'hello world, this is ' + self.address0)
        bulletin = classes.Bulletin(topic, content)
        assert hasattr(bulletin, 'topic') and isinstance(bulletin.topic, interfaces.AbstractTopic)
        assert hasattr(bulletin, 'content') and isinstance(bulletin.content, interfaces.AbstractContent)
        assert hasattr(bulletin, 'ts') and type(bulletin.ts) is int
        assert hasattr(bulletin, 'nonce') and type(bulletin.nonce) is int

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_bytes_hash_methods_return_proper_types(self):
        topic = interfaces.AbstractTopic(b'123', b'descriptor')
        content = classes.Content.from_content(b'hello world, this is ' + self.address0)
        bulletin = classes.Bulletin(topic, content)
        assert hasattr(bulletin, '__bytes__') and callable(bulletin.__bytes__)
        assert type(bulletin.__bytes__()) is bytes
        assert hasattr(bulletin, '__hash__') and callable(bulletin.__hash__)
        assert type(bulletin.__hash__()) is int

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_check_hash_returns_bool(self):
        topic = interfaces.AbstractTopic(b'123', b'descriptor')
        content = classes.Content.from_content(b'hello world, this is ' + self.address0)
        bulletin = classes.Bulletin(topic, content)
        assert hasattr(bulletin, 'check_hash') and callable(bulletin.check_hash)
        assert type(bulletin.check_hash()) is bool

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_hashcash_changes_nonce_and_makes_check_hash_return_true(self):
        topic = interfaces.AbstractTopic(b'123', b'descriptor')
        content = classes.Content.from_content(b'hello world, this is ' + self.address0)
        bulletin = classes.Bulletin(topic, content)
        assert hasattr(bulletin, 'hashcash') and callable(bulletin.hashcash)

        # ensure the nonce is wrong
        if bulletin.check_hash():
            bulletin.nonce -= 1

        assert not bulletin.check_hash()
        nonce0 = bulletin.nonce
        assert isinstance(bulletin.hashcash(), interfaces.AbstractBulletin)
        assert bulletin.nonce != nonce0
        assert bulletin.check_hash()

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Bulletin_pack_and_unpack_return_correct_types_and_values(self):
        descriptor = b'node beacon channel'
        topic_id = sha256(descriptor).digest()
        topic = interfaces.AbstractTopic(topic_id)
        content = classes.Content.from_content(b'hello world, this is ' + self.address0)
        bulletin = classes.Bulletin(topic, content)
        assert hasattr(bulletin, 'pack') and callable(bulletin.pack)
        assert hasattr(classes.Bulletin, 'unpack') and callable(classes.Bulletin.unpack)

        packed = bulletin.pack()
        assert type(packed) is bytes
        assert packed[:32] == topic_id
        assert packed[32:64] == content.id
        assert int.from_bytes(packed[64:68], 'big') == bulletin.ts
        assert int.from_bytes(packed[68:72], 'big') == bulletin.nonce

        unpacked = classes.Bulletin.unpack(packed)
        assert type(unpacked) is classes.Bulletin
        assert unpacked == bulletin


    # Node tests
    def test_Node_instantiates_with_specified_properties(self):
        node = classes.Node(self.address0)
        assert hasattr(node, 'address') and type(node.address) is bytes
        assert hasattr(node, 'content_seen') and type(node.content_seen) is set
        assert hasattr(node, 'topics_followed') and type(node.topics_followed) is set
        assert hasattr(node, 'connections') and type(node.connections) is set
        assert hasattr(node, 'data') and type(node.data) is dict
        assert hasattr(node, '_seed') and node._seed is None
        assert hasattr(node, '_skey') and node._skey is None
        assert hasattr(node, '_vkey') and type(node._vkey) is VerifyKey
        assert hasattr(node, '_inbound') and type(node._inbound) is SimpleQueue
        assert hasattr(node, '_outbound') and type(node._outbound) is SimpleQueue
        assert hasattr(node, '_actions') and type(node._actions) is SimpleQueue
        assert hasattr(node, '_new_bulletins') and type(node._new_bulletins) is SimpleQueue
        assert hasattr(node, '_message_sender') and node._message_sender is None
        assert hasattr(node, '_message_handler') and node._message_handler is None
        assert hasattr(node, '_action_handler') and node._action_handler is None
        assert hasattr(node, '_bulletin_handler') and node._bulletin_handler is None

    def test_Node_from_seed_instantiates_with_specified_properties(self):
        node = classes.Node.from_seed(self.seed0)
        assert hasattr(node, 'address') and type(node.address) is bytes
        assert hasattr(node, 'content_seen') and type(node.content_seen) is set
        assert hasattr(node, 'topics_followed') and type(node.topics_followed) is set
        assert hasattr(node, 'connections') and type(node.connections) is set
        assert hasattr(node, 'data') and type(node.data) is dict
        assert hasattr(node, '_seed') and type(node._seed) is bytes
        assert hasattr(node, '_skey') and type(node._skey) is SigningKey
        assert hasattr(node, '_vkey') and type(node._vkey) is VerifyKey
        assert hasattr(node, '_inbound') and type(node._inbound) is SimpleQueue
        assert hasattr(node, '_outbound') and type(node._outbound) is SimpleQueue
        assert hasattr(node, '_actions') and type(node._actions) is SimpleQueue
        assert hasattr(node, '_new_bulletins') and type(node._new_bulletins) is SimpleQueue
        assert hasattr(node, '_message_sender') and node._message_sender is None
        assert hasattr(node, '_message_handler') and node._message_handler is None
        assert hasattr(node, '_action_handler') and node._action_handler is None
        assert hasattr(node, '_bulletin_handler') and node._bulletin_handler is None

    def test_Node_instance_not_from_seed_cannot_sign_messages(self):
        node = classes.Node(self.address0)
        with self.assertRaises(ValueError) as e:
            node.send_message(self.address1, b'hello world')
        assert str(e.exception) == "Cannot send a message without a SigningKey set."

    def test_Node_instances_from_seed_can_encrypt_and_decrypt_Messages(self):
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

    def test_Node_register_message_sender_raises_TypeError_for_invalid_arg(self):
        # setup
        node = classes.Node(self.address0)
        class Thing:
            ...

        with self.assertRaises(TypeError) as e:
            node.register_message_sender(Thing())
        assert str(e.exception) == 'sender must fulfill SupportsSendMessage duck type'

    def test_Node_register_message_sender_sends_messages_on_process(self):
        class MessageSender(interfaces.SupportsSendMessage):
            nodes: set[interfaces.AbstractNode]

            def __init__(self, nodes: list[interfaces.AbstractNode]):
                self.nodes = set(nodes)

            def send(self, msg: interfaces.AbstractMessage) -> None:
                if not isinstance(msg, interfaces.AbstractMessage):
                    raise TypeError('msg must implement AbstractMessage')
                if msg.dst in [n.address for n in self.nodes]:
                    node = [n for n in self.nodes if n.address == msg.dst][0]
                    node.receive_message(msg)

        # set up
        node0 = classes.Node.from_seed(self.seed0)
        node1 = classes.Node.from_seed(self.seed1)
        sender = MessageSender([node0, node1])

        # preconditions
        assert node0._message_sender is None
        assert node0.action_count() == 0
        assert node0._outbound.qsize() == 0
        assert node1.action_count() == 0
        assert node1._inbound.qsize() == 0

        # register sender
        node0.register_message_sender(sender)
        assert node0._message_sender is not None

        # queue up sending the message
        node0.send_message(node1.address, b'hello node1')
        assert node0.action_count() == 1
        assert node0._outbound.qsize() == 1

        # send
        node0.process()

        # check to make sure it arrived
        assert node0.action_count() == 0
        assert node0._outbound.qsize() == 0
        assert node1.action_count() == 1
        assert node1._inbound.qsize() == 1

    def test_Node_register_message_handler_raises_TypeError_for_invalid_arg(self):
        # setup
        node = classes.Node(self.address0)
        class Thing:
            ...

        with self.assertRaises(TypeError) as e:
            node.register_message_handler(Thing())
        assert str(e.exception) == 'handler must fulfill SupportsHandleMessage duck type'

    @patch.multiple(interfaces.AbstractAction, __abstractmethods__=set())
    def test_Node_register_message_handler_handles_messages_on_process(self):
        class MessageHandler(interfaces.SupportsHandleMessage):
            nodes: set[interfaces.AbstractNode]

            def __init__(self, nodes: list[interfaces.AbstractNode]) -> None:
                self.nodes = set(nodes)

            def handle(self, msg: interfaces.AbstractMessage) -> None:
                if msg.dst in [n.address for n in self.nodes]:
                    node = [n for n in self.nodes if n.address == msg.dst][0]
                    node.queue_action(interfaces.AbstractAction('store_and_forward', {"msg": msg.body}))

        # setup
        node = classes.Node.from_seed(self.seed0)
        handler = MessageHandler([node])
        message = classes.Message(node.address, node.address, b'hello world')
        message.encrypt().hashcash().sign(node._skey)

        # preconditions
        assert node._message_handler is None
        assert node._inbound.qsize() == 0
        assert node._actions.qsize() == 0

        # register handler and receive message
        node.register_message_handler(handler)
        assert node._message_handler is not None
        node.receive_message(message)
        assert node._inbound.qsize() == 1

        # process
        node.process()
        assert node._inbound.qsize() == 0
        assert node._actions.qsize() == 1

    def test_Node_register_action_handler_raises_TypeError_for_invalid_arg(self):
        # setup
        node = classes.Node(self.address0)
        class Thing:
            ...

        with self.assertRaises(TypeError) as e:
            node.register_action_handler(Thing())
        assert str(e.exception) == 'handler must fulfill SupportsHandleAction duck type'

    @patch.multiple(interfaces.AbstractAction, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractConnection, __abstractmethods__=set())
    def test_Node_register_action_handler_handles_actions_on_process(self):
        actions_handled = []

        class ActionHandler(interfaces.SupportsHandleAction):
            node: interfaces.AbstractNode

            def __init__(self, node: interfaces.AbstractNode):
                self.node = node

            def handle(self, action: interfaces.AbstractAction):
                if action.name == 'store_and_forward':
                    self.store_and_forward(action)

            def store_and_forward(self, action: interfaces.AbstractAction) -> None:
                if sha256(action.data['msg']).digest() not in self.node.content_seen:
                        nonlocal actions_handled
                        actions_handled.append(action)
                        self.node.content_seen.add(sha256(action.data['msg']).digest())
                        if len(self.node.connections):
                            for c in self.node.connections:
                                neighbor = [n for n in c.nodes if n is not self.node][0]
                                self.node.send_message(neighbor.address, action.data['msg'])

        # setup
        node = classes.Node.from_seed(self.seed0)
        neighbor = classes.Node(self.address1)
        connection = interfaces.AbstractConnection(set([node, neighbor]))
        node.add_connection(connection)
        node.register_action_handler(ActionHandler(node))

        # precondition
        assert node.action_count() == 0

        # test
        node._actions.put(interfaces.AbstractAction('store_and_forward', {'msg': b'hello'}))
        assert node.action_count() == 1
        assert node._actions.qsize() == 1
        node.process()
        assert node.action_count() == 1
        assert node._actions.qsize() == 0
        assert node._outbound.qsize() == 1

    def test_Node_register_bulletin_handler_raises_TypeError_for_invalid_arg(self):
        # setup
        node = classes.Node(self.address0)
        class Thing:
            ...

        with self.assertRaises(TypeError) as e:
            node.register_bulletin_handler(Thing())
        assert str(e.exception) == 'handler must fulfill SupportsHandleRetrieveListQueryBulletin duck type'

    def test_Node_register_buulletin_handler_handles_new_bulletins_on_process(self):
        bulletins_handled = []
        class BulletinHandler(interfaces.SupportsHandleRetrieveListQueryBulletin):
            node: interfaces.AbstractNode
            storage: list[interfaces.AbstractBulletin]

            def __init__(self, node: interfaces.AbstractNode) -> None:
                if not isinstance(node, interfaces.AbstractNode):
                    raise TypeError('node must implement AbstractNode')
                self.node = node
                self.storage = []

            def handle(self, bulletin: interfaces.AbstractBulletin) -> None:
                if bulletin.topic in self.node.topics_followed:
                    self.storage.append(bulletin)
                nonlocal bulletins_handled
                bulletins_handled.append(bulletin)

            def retrieve(self, topic_id: bytes, content_id: bytes) -> interfaces.AbstractBulletin:
                result = [b for b in self.storage if b.topic.id == topic_id and b.content.id == content_id]
                return result[0] if len(result) else None

            def list(self, topic_id: bytes) -> list[bytes]:
                return [b for b in self.storage if b.topic.id == topic_id]

            def query(self, query: dict) -> set[interfaces.AbstractBulletin]:
                return self.storage

        # setup
        node = classes.Node.from_seed(self.seed0)
        topic0 = classes.Topic.from_descriptor(b'apparently uninteresting')
        topic1 = classes.Topic.from_descriptor(b'apparently interesting')
        content = classes.Content.from_content(b'this is some kind of information')
        bulletin0 = classes.Bulletin(topic0, content)
        bulletin1 = classes.Bulletin(topic1, content)
        node.register_bulletin_handler(BulletinHandler(node))
        node.subscribe(topic1)

        # preconditions
        assert len(bulletins_handled) == 0
        assert len(node.content_seen) == 0
        assert node._new_bulletins.qsize() == 0

        # test 1
        node.mark_as_seen(bulletin0)
        assert node.action_count() == 1
        assert node._new_bulletins.qsize() == 1
        node.process()
        assert node.action_count() == 0
        assert len(node._bulletin_handler.storage) == 0
        assert len(bulletins_handled) == 1

        # test 2
        node.mark_as_seen(bulletin1)
        assert node.action_count() == 1
        node.process()
        assert node.action_count() == 0
        assert len(node._bulletin_handler.storage) == 1
        assert len(bulletins_handled) == 2

    def test_Node_add_connection_raises_TypeError_on_non_AbstractConnection_arg(self):
        node = classes.Node(self.address0)
        with self.assertRaises(TypeError) as e:
            node.add_connection('does not implement AbstractConnection')
        assert str(e.exception) == 'connection must implement AbstractConnection'

    def test_Node_drop_connection_raises_TypeError_on_non_AbstractConnection_arg(self):
        node = classes.Node(self.address0)
        with self.assertRaises(TypeError) as e:
            node.drop_connection('does not implement AbstractConnection')
        assert str(e.exception) == 'connection must implement AbstractConnection'

    @patch.multiple(interfaces.AbstractConnection, __abstractmethods__=set())
    def test_Node_add_connection_and_drop_connection_work(self):
        node0 = classes.Node(self.address0)
        node1 = classes.Node(self.address1)
        connection = interfaces.AbstractConnection(set([node0, node1]))

        # precondition
        assert len(node0.connections) == 0

        # test 1
        node0.add_connection(connection)
        assert len(node0.connections) == 1
        assert connection in node0.connections

        # test 2
        node0.drop_connection(connection)
        assert len(node0.connections) == 0

    def test_Node_count_connections_returns_int_number_of_connections(self):
        node = classes.Node.from_seed(self.seed0)
        node.connections.add('substitute')
        assert type(node.count_connections()) is int
        assert node.count_connections() == len(node.connections)

    def test_Node_receive_message_raises_TypeError_for_non_AbstractMessage_arg(self):
        node = classes.Node(self.address0)

        with self.assertRaises(TypeError) as e:
            node.receive_message('does not implement AbstractMessage')
        assert str(e.exception) == 'message must implement AbstractMessage'

    def test_Node_receive_message_drops_invalid_messages(self):
        debug_messages = []

        def custom_debugger(msg: str) -> None:
            nonlocal debug_messages
            debug_messages.append(msg)

        # setup
        misc.deregister_debug_handler(print)
        misc.register_debug_handler(custom_debugger)
        node = classes.Node.from_seed(self.seed0)
        wrong_dst = classes.Message(node.address, self.seed1, b'hello world')
        too_old = classes.Message(node.address, node.address, b'hello world')
        too_old.ts -= misc.MESSAGE_TTL + 2
        unhashcashed = classes.Message(node.address, node.address, b'hello world')
        while unhashcashed.check_hash(): # ensure it does not meet the hashcash threshold
            unhashcashed = classes.Message(node.address, node.address, b'hello world')
        unsigned = classes.Message(node.address, node.address, b'hello world')
        unsigned.hashcash()
        unencrypted = classes.Message(node.address, node.address, b'hello world')
        unencrypted.hashcash().sign(node._skey)
        bad_signature = classes.Message(node.address, node.address, b'hello world')
        bad_signature.hashcash()
        bad_signature.sig = node.address + node.address

        # tests
        node.receive_message(wrong_dst)
        assert "Node.receive_message: message dropped for improper destination" == debug_messages.pop()
        node.receive_message(too_old)
        assert "Node.receive_message: old message discarded" == debug_messages.pop()
        node.receive_message(unhashcashed)
        assert "Node.receive_message: message failed hashcash check" == debug_messages.pop()
        node.receive_message(bad_signature)
        assert "Node.receive_message: message signature failed verification" == debug_messages.pop()
        node.receive_message(unencrypted)
        assert "Node.receive_message: unencrypted message encountered" == debug_messages.pop()
        node.receive_message(unsigned)
        assert "Node.receive_message: unsigned message rejected" == debug_messages.pop()
        assert len(debug_messages) == 0

        # return debug to its original state
        misc.deregister_debug_handler(custom_debugger)
        misc.register_debug_handler(print)

    def test_Node_send_message_raises_TypeError_for_non_bytes_dst_or_msg(self):
        node = classes.Node(self.address0)

        with self.assertRaises(TypeError) as e:
            node.send_message('not bytes dst', b'bytes msg')
        assert str(e.exception) == 'dst must be bytes'

        with self.assertRaises(TypeError) as e:
            node.send_message(b'bytes dst', 'not bytes msg')
        assert str(e.exception) == 'msg must be bytes'

    def test_Node_send_message_raises_ValueError_if_no_skey_present(self):
        node = classes.Node(self.address0)

        with self.assertRaises(ValueError) as e:
            node.send_message(b'bytes dst', b'bytes msg')
        assert str(e.exception) == 'Cannot send a message without a SigningKey set.'

    @patch.multiple(interfaces.AbstractConnection, __abstractmethods__=set())
    def test_Node_send_message_queues_outbound_message_when_connection_present(self):
        # setup
        node0 = classes.Node.from_seed(self.seed0)
        node1 = classes.Node(self.address1)
        connection = interfaces.AbstractConnection([node0, node1])
        node0.add_connection(connection)

        # precondition
        assert node0._outbound.qsize() == 0

        # test
        node0.send_message(node1.address, b'hello node1')
        assert node0._outbound.qsize() == 1

    def test_Node_send_message_drops_outbound_message_when_connection_missing(self):
        # setup
        node0 = classes.Node.from_seed(self.seed0)
        node1 = classes.Node(self.address1)
        connection = interfaces.AbstractConnection([node0, node1])
        node0.add_connection(connection)
        debug_message = ''
        def debug_handler(msg: str):
            nonlocal debug_message
            debug_message = msg
        misc.deregister_debug_handler(print)
        misc.register_debug_handler(debug_handler)

        # precondition
        assert node0._outbound.qsize() == 0

        # test
        node0.send_message(self.address2, b'hello world')
        assert node0._outbound.qsize() == 0
        assert debug_message == 'cannot deliver message due to lack of connection'

        # clean up
        misc.deregister_debug_handler(debug_handler)
        misc.register_debug_handler(print)

    def test_Node_send_message_queues_outbound_message_when_no_connections_set(self):
        node0 = classes.Node.from_seed(self.seed0)

        # precondition
        assert node0._outbound.qsize() == 0

        # test
        node0.send_message(self.address1, b'hello node1')
        assert node0._outbound.qsize() == 1

    def test_Node_subscribe_raises_TypeError_for_non_AbstractTopic(self):
        node = classes.Node(self.address0)
        with self.assertRaises(TypeError) as e:
            node.subscribe('not a topic')
        assert str(e.exception) == 'topic must implement AbstractTopic'
        with self.assertRaises(TypeError) as e:
            node.subscribe(b'still not a topic')
        assert str(e.exception) == 'topic must implement AbstractTopic'

    def test_Node_topics_followed_has_len_2_on_instantiate(self):
        node = classes.Node(self.address0)
        assert len(node.topics_followed) == 2

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_Node_subscribe_adds_topic_to_topics_followed(self):
        node = classes.Node(self.address0)
        assert len(node.topics_followed) == 2
        node.subscribe(interfaces.AbstractTopic(b'abcd'))
        assert len(node.topics_followed) == 3
        assert len([t for t in node.topics_followed if t.id == b'abcd']) == 1

    def test_Node_unsubscribe_removes_topic_from_topics_followed(self):
        node = classes.Node(self.address0)
        topic = list(node.topics_followed)[0]
        assert topic in node.topics_followed
        node.unsubscribe(topic)
        assert topic not in node.topics_followed

    def test_Node_publish_queues_incoming_message_containing_bulletin(self):
        # setup
        node = classes.Node.from_seed(self.seed0)
        topic = classes.Topic.from_descriptor(b'node beacon channel')
        content = classes.Content.from_content(b'\x00' + node.address)
        bulletin = classes.Bulletin(topic, content)

        # precondition
        assert node.action_count() == 0

        # test
        node.publish(bulletin)
        assert node.action_count() == 1
        assert node._inbound.qsize() == 1

    def test_Node_queue_action_raises_TypeError_for_non_AbstractAction_arg(self):
        node = classes.Node.from_seed(self.seed0)

        with self.assertRaises(TypeError) as e:
            node.queue_action('does not implement AbstractAction')
        assert str(e.exception) == 'act must implement AbstractAction'

    @patch.multiple(interfaces.AbstractAction, __abstractmethods__=set())
    def test_Node_queue_action_adds_AbstractAction_to_actions_queue(self):
        node = classes.Node.from_seed(self.seed0)
        action = interfaces.AbstractAction('do a thing', {})

        # precondition
        assert node._actions.qsize() == 0

        # test
        node.queue_action(action)
        assert node._actions.qsize() == 1

    def test_Node_action_count_returns_int_number_of_items_in_actions_queue(self):
        node = classes.Node.from_seed(self.seed0)

        node._actions.put('something')
        assert type(node.action_count()) is int
        assert node.action_count() == node._actions.qsize()


    # Neighbor tests
    def test_Neighbor_implements_AbstractNode_and_isinstance_of_Node(self):
        neighbor = classes.Neighbor(self.address1)
        assert isinstance(neighbor, interfaces.AbstractNode)
        assert isinstance(neighbor, classes.Node)

    def test_Neighbor_has_address_vkey_and_empty_topics_followed(self):
        neighbor = classes.Neighbor(self.address1)
        assert hasattr(neighbor, 'address') and type(neighbor.address) is bytes
        assert hasattr(neighbor, '_vkey') and type(neighbor._vkey) is VerifyKey
        assert hasattr(neighbor, 'topics_followed') and type(neighbor.topics_followed) is set
        assert len(neighbor.topics_followed) == 0


    # Action tests
    def test_Action_init_raises_TypeError_for_non_str_name(self):
        with self.assertRaises(TypeError) as e:
            classes.Action(b'not a str', {})
        assert str(e.exception) == 'name must be str'
        classes.Action('str name', {})

    def test_Action_init_raises_TypeError_for_non_dict_data(self):
        with self.assertRaises(TypeError) as e:
            classes.Action('str name', 'not dict data')
        assert str(e.exception) == 'data must be dict'
        classes.Action('str name', {'data': 'is dict'})


    # Connection tests
    def test_Connection_init_raises_TypeError_for_non_set_or_list_input(self):
        with self.assertRaises(TypeError) as e:
            classes.Connection('not a list or set')
        assert str(e.exception) == 'nodes must be list or set'

    def test_Connection_init_raises_ValueError_for_incorrect_number_of_nodes(self):
        with self.assertRaises(ValueError) as e:
            classes.Connection(['just one node'])
        assert str(e.exception) == 'a Connection must connect exactly 2 nodes'

    def test_Connection_init_raises_TypeError_for_non_nodes(self):
        with self.assertRaises(TypeError) as e:
            classes.Connection(['not a node', 'also not a node'])
        assert str(e.exception) == 'each node must implement AbstractNode'

    def test_Connection_init_raises_no_errors_for_set_or_list_of_nodes(self):
        node0 = classes.Node(self.address0)
        node1 = classes.Node(self.address1)
        classes.Connection([node0, node1])
        classes.Connection(set([node0, node1]))

    def test_Connection_instantiates_with_nodes_and_data(self):
        node0 = classes.Node(self.address0)
        node1 = classes.Node(self.address1)
        connection = classes.Connection([node0, node1])
        assert hasattr(connection, 'nodes') and type(connection.nodes) is set
        assert hasattr(connection, 'data') and type(connection.data) is dict


if __name__ == '__main__':
    unittest.main()
