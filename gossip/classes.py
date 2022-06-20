from __future__ import annotations
from gossip.interfaces import (
    AbstractBulletin,
    AbstractTopic,
    SupportsHandleAction,
    SupportsHandleMessage,
    SupportsSendMessage,
    AbstractAction,
    AbstractConnection,
    AbstractMessage,
    AbstractNode,
)
from gossip.misc import(
    MESSAGE_TTL,
    DIFFICULTY_BITS,
    check_difficulty,
    format_address,
    debug,
)
from hashlib import sha256, shake_256
from nacl.public import SealedBox
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from queue import SimpleQueue
from random import randint
import struct
from time import time


class Message(AbstractMessage):
    """Message model contains the source, destination, content, and
        optional signature and metadata.
    """
    def __repr__(self) -> str:
        return f"{format_address(self.src)}->{format_address(self.dst)}: " + \
            f"{format_address(sha256(self.body).digest())}"

    def __bytes__(self) -> bytes:
        return self.src + self.dst + self.body

    def __hash__(self) -> int:
        """Enable inclusion in sets."""
        return hash(bytes(self))

    def get_header(self) -> bytes:
        """Produce a message header from non-content data."""
        return self.src + self.dst + self.ts.to_bytes(4, 'big') + self.nonce.to_bytes(4, 'big')

    def check_hash(self) -> bool:
        """Check that the hash of a message meets the difficulty threshold."""
        digest = shake_256(self.get_header() + self.body).digest(int(DIFFICULTY_BITS//8)+1)
        return check_difficulty(digest)

    def pow(self) -> None:
        """Increment the nonce until check_hash() returns True."""
        while (not self.check_hash()):
            self.nonce = (self.nonce + 1) % 2**32

    def pack(self) -> bytes:
        """Pack the data with struct."""
        fstr = '!32s32sii64s' + str(len(self.body)) + 's'
        return struct.pack(fstr, self.dst, self.src, self.ts, self.nonce, self.sig, self.body)

    @classmethod
    def unpack(cls, packed: bytes) -> AbstractMessage:
        """Unpack the data with struct."""
        fstr = '!32s32sii64s' + str(len(packed) - 136) + 's'
        (dst, src, ts, nonce, sig, body) = struct.unpack(fstr, packed)
        return Message(src, dst, body, ts, nonce, sig)

    def sign(self, skey: SigningKey) -> SignedMessage:
        """Generate a signature for the message."""
        sig = skey.sign(bytes(self))
        self.sig = sig[:64]
        return sig

    def verify(self) -> bool:
        """Verify the message signature"""
        try:
            vkey = VerifyKey(self.src)
            sig = SignedMessage(self.sig + bytes(self))
            vkey.verify(sig)
            return True
        except:
            return False

    def encrypt(self) -> None:
        """Encrypt using ephemeral ECDHE."""
        sealed_box = SealedBox(VerifyKey(self.dst).to_curve25519_public_key())
        self.body = sealed_box.encrypt(self.body)

    def decrypt(self, skey: SigningKey) -> None:
        """Decrypt using ephemeral ECDHE."""
        if type(skey) is not SigningKey:
            raise TypeError('skey must be a valid SigningKey')
        if bytes(skey.verify_key) != self.dst:
            raise ValueError('Must use the skey of the receiver to decrypt.')

        privk = skey.to_curve25519_private_key()
        sealed_box = SealedBox(privk)
        self.body = sealed_box.decrypt(self.body)


class Topic(AbstractTopic):
    @classmethod
    def from_descriptor(cls, descriptor: bytes) -> Topic:
        if type(descriptor) is not bytes:
            raise TypeError("descriptor must be bytes")

        id = sha256(descriptor).digest()
        return cls(id, descriptor)


class Bulletin(AbstractBulletin):
    def __init__(self, topic: AbstractTopic, content: bytes) -> None:
        if not isinstance(topic, AbstractTopic):
            raise TypeError("topic must implement AbstractTopic")
        if type(content) is not bytes:
            raise TypeError("content must be bytes")

        self.topic = topic
        self.content = content

    def __bytes__(self) -> bytes:
        return self.pack()

    def __hash__(self) -> int:
        return hash(bytes(self))

    def pack(self) -> bytes:
        fstr = '!32s' + str(len(self.content)) + 's'
        return struct.pack(fstr, self.topic.id, self.content)

    @classmethod
    def unpack(cls, data: bytes) -> Bulletin:
        fstr = '!32s' + str(len(data) - 32) + 's'
        topic_id, content = struct.unpack(fstr, data)
        return cls(Topic(topic_id), content)


class Node(AbstractNode):
    def __init__(self, address: bytes) -> None:
        """Create a node from its address (public key bytes)."""
        self.address = address
        self.msgs_seen = set()
        self.connections = set()
        self.bulletins = set()
        # subscribe the node to messages directed to itself
        self.topics_followed = set([
            Topic.from_descriptor(address),
            Topic.from_descriptor(b'node beacon channel')
        ])
        self.data = {}
        self._vkey = VerifyKey(address)
        self._seed = None
        self._skey = None
        self._inbound = SimpleQueue()
        self._outbound = SimpleQueue()
        self._actions = SimpleQueue()
        self._message_handler = None
        self._message_sender = None
        self._action_handler = None

    @classmethod
    def from_seed(cls, seed: bytes) -> Node:
        """Create a node from a seed filling out _skey."""
        skey = SigningKey(seed)
        node = cls(bytes(skey.verify_key))
        node._skey = skey
        node._seed = seed
        return node

    def __lt__(self, other: Node) -> bool:
        return self.address < other.address

    def __repr__(self) -> str:
        if self._seed is not None:
            return "{'address': '" + format_address(self.address) + "','seed':'" + self._seed.hex() + "}"
        else:
            return "{'address': '" + format_address(self.address) + "'}"

    def register_message_sender(self, sndr: SupportsSendMessage) -> None:
        """Register the message sender."""
        if not hasattr(sndr, 'send') or not callable(sndr.send):
            raise TypeError('sndr must fulfill SupportsSendMessage duck type')
        self._message_sender = sndr

    def register_message_handler(self, hndlr: SupportsHandleMessage) -> None:
        """Register the incoming message handler."""
        if not hasattr(hndlr, 'handle') or not callable(hndlr.handle):
            raise TypeError('hndlr must fulfill SupportsHandleMessage duck type')
        self._message_handler = hndlr

    def register_action_handler(self, hndlr: SupportsHandleAction) -> None:
        """Register the action handler."""
        if not hasattr(hndlr, 'handle') or not callable(hndlr.handle):
            raise TypeError('hndlr must fulfill SupportsHandleAction duck type')
        self._action_handler = hndlr

    def add_connection(self, connection: AbstractConnection) -> None:
        """Add the specified connection."""
        if not isinstance(connection, AbstractConnection):
            raise TypeError('connection must implement AbstractConnection')
        self.connections.add(connection)

    def drop_connection(self, connection: AbstractConnection) -> None:
        """Drop the specified connection."""
        if not isinstance(connection, AbstractConnection):
            raise TypeError('connection must implement AbstractConnection')
        self.connections.remove(connection)

    def count_connections(self) -> int:
        return len(self.connections)

    def receive_message(self, message: AbstractMessage) -> None:
        """Queue up an incoming message if its signature is valid or
            ignored.
        """
        if not isinstance(message, AbstractMessage):
            raise TypeError('message must implement AbstractMessage')

        global MESSAGE_TTL

        if int(time()) > (message.ts + MESSAGE_TTL):
            debug("Node.receive_message: old message discarded")
        elif message.sig is not None:
            if message.verify():
                message.decrypt(self._skey)
                self._inbound.put(message)
            else:
                debug("Node.receive_message: message signature failed verification")
        else:
            debug("Node.receive_message: unsigned message rejected")

    def send_message(self, dst: bytes, msg: bytes) -> None:
        """Queue up an outgoing message."""
        if type(dst) is not bytes:
            raise TypeError("dst must be bytes")
        if type(msg) is not bytes:
            raise TypeError("msg must be bytes")
        if self._skey is None:
            raise ValueError("Cannot send a message without a SigningKey set.")

        message = Message(self.address, dst, msg)
        message.encrypt()
        message.sign(self._skey)

        if len(self.connections):
            if len([c for c in self.connections if dst in [n.address for n in c.nodes]]):
                self._outbound.put(message)
            else:
                debug("cannot deliver message due to lack of connection")
        else:
            self._outbound.put(message)

    def subscribe(self, topic: bytes) -> None:
        if type(topic) is not bytes:
            raise TypeError('topic must be exactly 32 bytes')
        if len(topic) != 32:
            raise ValueError('topic must be exactly 32 bytes')

        self.topics_followed.add(topic)

    def unsubscribe(self, topic: bytes) -> None:
        if topic in self.topics_followed:
            self.topics_followed.remove(topic)

    def publish(self, bulletin: AbstractBulletin) -> None:
        """Publish a bulletin by engaging the store_and_forward action."""
        message = Message(self.address, self.address, bytes(bulletin))
        message.encrypt()
        message.sign(self._skey)
        self.receive_message(message)

    def queue_action(self, act: AbstractAction) -> None:
        """Queue an action to be processed by the action handler."""
        if not isinstance(act, AbstractAction):
            raise TypeError('act must implement AbstractAction')
        self._actions.put(act)

    def process(self) -> None:
        """Process actions for this node once."""
        if self._outbound.qsize() > 0 and self._message_sender is not None:
            self._message_sender.send(self._outbound.get())
        if self._inbound.qsize() > 0 and self._message_handler is not None:
            self._message_handler.handle(self._inbound.get())
        if self._actions.qsize() > 0 and self._action_handler is not None:
            self._action_handler.handle(self._actions.get())

    def action_count(self) -> int:
        """Count the size of pending messages and actions."""
        return self._outbound.qsize() + self._inbound.qsize() + self._actions.qsize()


class Neighbor(Node):
    def __init__(self, address: bytes) -> None:
        """Create a neighbor from its address (public key bytes)."""
        super().__init__(address)
        self.topics_followed = set()


class Action(AbstractAction):
    """Action model contains the name and data for an action a Node will
        take by passing to the registered action handler.
    """
    def __init__(self, name: str, data: dict) -> None:
        self.name = name
        self.data = data


class Connection(AbstractConnection):
    """Connection model represent an edge connecting two Nodes together."""
    def __init__(self, nodes: list[AbstractNode]) -> None:
        if type(nodes) is not list or len(nodes) != 2:
            raise Exception('a Connection must connect exactly 2 nodes')
        for n in nodes:
            if not isinstance(n, AbstractNode):
                raise Exception('a Connection must connect exactly 2 nodes')

        self.nodes = set(nodes)
        self.data = {}

    def __hash__(self) -> int:
        """Enable inclusion in sets."""
        node_list = list(self.nodes)
        node_list.sort()
        return hash(node_list[0].address + node_list[1].address)
