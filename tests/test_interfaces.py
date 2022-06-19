from unittest.mock import patch
from context import interfaces
import unittest


class TestInterfaces(unittest.TestCase):
    """Test suite for interfaces."""
    def test_imports_without_error(self):
        pass


    # AbstractTopic tests
    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_AbstractTopic_instantiates_with_id_and_descriptor(self):
        id = b'123'
        descriptor = b'321'
        topic = interfaces.AbstractTopic(id, descriptor)
        assert topic.id == id
        assert topic.descriptor == descriptor

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_AbstractTopic_repr_returns_str(self):
        id = b'123'
        descriptor = b'321'
        topic = interfaces.AbstractTopic(id, descriptor)
        assert type(repr(topic)) is str

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_AbstractTopic_bytes_returns_id_bytes(self):
        id = b'123'
        descriptor = b'321'
        topic = interfaces.AbstractTopic(id, descriptor)
        assert type(bytes(topic)) is bytes
        assert bytes(topic) == id

    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    def test_AbstractTopic_hash_returns_int(self):
        id = b'123'
        descriptor = b'321'
        topic = interfaces.AbstractTopic(id, descriptor)
        assert type(hash(topic)) is int


    # AbstractBulletin test
    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractBulletin, __abstractmethods__=set())
    def test_AbstractBulletin_instantiates_with_topic_and_content(self):
        id = b'123'
        descriptor = b'321'
        content = b'hello world'
        topic = interfaces.AbstractTopic(id, descriptor)
        bulletin = interfaces.AbstractBulletin(topic, content)
        assert bulletin.topic == topic
        assert bulletin.content == content


    # AbstractAction test
    @patch.multiple(interfaces.AbstractAction, __abstractmethods__=set())
    def test_AbstractAction_instantiates_with_name_and_data(self):
        name = 'store_and_forward'
        data = {'test': 'data'}
        act = interfaces.AbstractAction(name, data)
        assert act.name == name
        assert act.data == data


    # AbstractMessage tests
    @patch.multiple(interfaces.AbstractMessage, __abstractmethods__=set())
    def test_AbstractMessage_instantiates_with_src_dst_and_msg(self):
        src = b'src'
        dst = b'dst'
        body = b'hello'
        message = interfaces.AbstractMessage(src, dst, body)
        assert message.src == src
        assert message.dst == dst
        assert message.body == body

    @patch.multiple(interfaces.AbstractMessage, __abstractmethods__=set())
    def test_AbstractMessage_instantiates_with_int_ts_and_int_nonce(self):
        src = b'src'
        dst = b'dst'
        body = b'hello'
        message = interfaces.AbstractMessage(src, dst, body)
        assert type(message.ts) is int
        assert type(message.nonce) is int

    @patch.multiple(interfaces.AbstractMessage, __abstractmethods__=set())
    def test_AbstractMessage_instantiates_with_empty_sig_and_metadata(self):
        src = b'src'
        dst = b'dst'
        body = b'hello'
        message = interfaces.AbstractMessage(src, dst, body)
        assert message.sig is None
        assert type(message.metadata) is dict
        assert len(message.metadata.keys()) == 0


    # AbstractNode test
    @patch.multiple(interfaces.AbstractNode, __abstractmethods__=set())
    def test_AbstractNode_instantiates_with_address_and_is_hashable(self):
        node = interfaces.AbstractNode(b'nodeaddress')
        assert hasattr(node, 'address')
        assert type(node.address) is bytes
        assert type(node.__hash__()) is int


    # AbstractConnection test
    @patch.multiple(interfaces.AbstractNode, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractConnection, __abstractmethods__=set())
    def test_AbstractConnection_instantiates_with_nodes_and_empty_data(self):
        node0 = interfaces.AbstractNode(b'node0')
        node1 = interfaces.AbstractNode(b'node1')
        connection = interfaces.AbstractConnection(set([node0, node1]))
        assert type(connection.nodes) is set
        assert connection.nodes == set([node0, node1])
        assert type(connection.data) is dict
        assert len(connection.data.keys()) == 0


if __name__ == '__main__':
    unittest.main()
