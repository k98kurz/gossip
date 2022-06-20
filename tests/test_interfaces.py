from hashlib import sha256
from unittest.mock import patch
from context import interfaces
import unittest

from gossip import misc


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


    # AbstractContent test
    @patch.multiple(interfaces.AbstractContent, __abstractmethods__=set())
    def test_AbstractContent_instantiates_with_None_or_bytes_content(self):
        content = interfaces.AbstractContent(b'123')
        assert content.content is None
        content = interfaces.AbstractContent(b'123', b'hello world')
        assert type(content.content) is bytes


    # AbstractNode tests
    @patch.multiple(interfaces.AbstractNode, __abstractmethods__=set())
    def test_AbstractNode_instantiates_with_address_and_is_hashable(self):
        node = interfaces.AbstractNode(b'nodeaddress')
        assert hasattr(node, 'address')
        assert type(node.address) is bytes
        assert type(node.__hash__()) is int

    @patch.multiple(interfaces.AbstractBulletin, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractContent, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractNode, __abstractmethods__=set())
    def test_AbstractNode_mark_as_seen_adds_bulletin_to_content_seen(self):
        node = interfaces.AbstractNode(b'nodeaddress')
        descriptor = b'some topic of interest'
        topic_id = sha256(descriptor).digest()
        topic = interfaces.AbstractTopic(topic_id, descriptor)
        content_id = sha256(b'hello world').digest()
        content = interfaces.AbstractContent(content_id, b'hello world')
        bulletin = interfaces.AbstractBulletin(topic, content)

        # precondition
        assert len(node.content_seen) == 0

        # test
        node.mark_as_seen(bulletin)
        assert len(node.content_seen) == 1
        assert bulletin in node.content_seen

    @patch.multiple(interfaces.AbstractBulletin, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractContent, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractTopic, __abstractmethods__=set())
    @patch.multiple(interfaces.AbstractNode, __abstractmethods__=set())
    def test_AbstractNode_delete_old_content_removes_expired_bulletins(self):
        node = interfaces.AbstractNode(b'nodeaddress')
        descriptor = b'some topic of interest'
        topic_id = sha256(descriptor).digest()
        topic = interfaces.AbstractTopic(topic_id, descriptor)
        content_id = sha256(b'hello world').digest()
        content = interfaces.AbstractContent(content_id, b'hello world')
        bulletin = interfaces.AbstractBulletin(topic, content)
        bulletin.ts -= misc.CONTENT_TTL + 2
        node.content_seen.add(bulletin)

        # precondition
        assert len(node.content_seen) == 1

        # test
        deleted = node.delete_old_content()
        assert type(deleted) is int
        assert deleted == 1
        assert len(node.content_seen) == 0


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
