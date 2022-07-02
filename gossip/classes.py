from __future__ import annotations
from random import randint
from gossip.interfaces import (
    AbstractAction,
    AbstractBulletin,
    AbstractConnection,
    AbstractContent,
    AbstractMessage,
    AbstractNode,
    AbstractTopic,
    CryptoError,
    SupportsHandleAction,
    SupportsHandleMessage,
    SupportsHandleRetrieveListQueryBulletin,
    SupportsSendMessage,
)
from gossip.misc import(
    MESSAGE_DIFFICULTY,
    MESSAGE_TTL,
    TAPEHASH_CODE_SIZE,
    check_bulletin_difficulty,
    check_difficulty,
    format_address,
    debug,
)
from gossip.tapehash import tapehash1
from hashlib import sha256
from nacl.exceptions import TypeError as NaclTypeError
from nacl.public import SealedBox
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from secrets import token_bytes
import struct
from time import time


class NaclAdapter():
    def get_address_from_seed(self, seed: bytes) -> bytes:
        if type(seed) != bytes:
            raise TypeError('seed must be bytes')
        if len(seed) != 32:
            raise ValueError('seed must be 32 bytes')

        return bytes(SigningKey(seed).verify_key)

    def encrypt(self, plaintext: bytes, address: bytes) -> bytes:
        """Encrypt plaintext with Curve25519 ephemeral ECDHE."""
        if type(plaintext) is not bytes:
            raise TypeError('plaintext must be bytes')
        if type(address) is not bytes:
            raise TypeError('address must be bytes')
        if len(address) != 32:
            raise ValueError('address must be 32 bytes')

        sealed_box = SealedBox(VerifyKey(address).to_curve25519_public_key())
        return sealed_box.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, skey_seed: bytes) -> bytes:
        """Decrypt Curve25519 ephemeral ECDHE encrypted ciphertext."""
        if type(ciphertext) is not bytes:
            raise TypeError('ciphertext must be bytes')
        if type(skey_seed) is not bytes:
            raise TypeError('skey_seed must be bytes')
        if len(skey_seed) != 32:
            raise ValueError('skey_seed must be 32 bytes')

        try:
            sealed_box = SealedBox(SigningKey(skey_seed).to_curve25519_private_key())
            return sealed_box.decrypt(ciphertext)
        except NaclTypeError as e:
            raise CryptoError(str(e))

    def sign(self, message: bytes, skey_seed: bytes) -> bytes:
        """Create an Ed25519 signature."""
        if type(message) is not bytes:
            raise TypeError('message must be bytes')
        if type(skey_seed) is not bytes:
            raise TypeError('skey_seed must be bytes')
        if len(skey_seed) != 32:
            raise ValueError('skey_seed must be 32 bytes')

        skey = SigningKey(skey_seed)
        return skey.sign(message)[:64]

    def verify(self, signature: bytes, message: bytes, vkey: bytes) -> bool:
        """Verify an Ed25519 signature."""
        if type(signature) is not bytes:
            raise TypeError('signature must be bytes')
        if len(signature) != 64:
            raise ValueError('signature must be 64 bytes')
        if type(message) is not bytes:
            raise TypeError('message must be bytes')
        if type(vkey) is not bytes:
            raise TypeError('vkey must be bytes')
        if len(vkey) != 32:
            raise ValueError('vkey must be 32 bytes')

        try:
            vkey = VerifyKey(vkey)
            sig = SignedMessage(signature + message)
            vkey.verify(sig)
            return True
        except:
            return False


class Message(AbstractMessage):
    """Message model contains the source, destination, content, and
        optional signature and metadata.
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs, crypto_adapter = NaclAdapter())

    def __repr__(self) -> str:
        return f"{format_address(self.src)}->{format_address(self.dst)}: " + \
            f"{format_address(sha256(self.body).digest())}"

    def __bytes__(self) -> bytes:
        return self.src + self.dst + self.body

    def __hash__(self) -> int:
        """Enable inclusion in sets."""
        return hash(bytes(self))

    def __eq__(self, other: Message) -> bool:
        if type(other) != type(self):
            return False

        return self.src == other.src and self.dst == other.dst and \
            self.body == other.body and self.ts == other.ts and \
            self.nonce == other.nonce and self.sig == other.sig

    def get_header(self) -> bytes:
        """Produce a message header from non-content data."""
        return self.src + self.dst + self.ts.to_bytes(4, 'big') + self.nonce.to_bytes(4, 'big')

    def check_hash(self, difficulty: int = MESSAGE_DIFFICULTY) -> bool:
        """Check that the hash of a message meets the difficulty threshold."""
        digest = tapehash1(self.get_header() + self.body, TAPEHASH_CODE_SIZE)
        return check_difficulty(digest, difficulty)

    def hashcash(self, difficulty: int = MESSAGE_DIFFICULTY) -> Message:
        """Increment the nonce until check_hash() returns True."""
        while (not self.check_hash(difficulty)):
            self.nonce = (self.nonce + 1) % 2**32
        return self

    def prepare_for_send(self, skey_seed: bytes, difficulty: int = None) -> Message:
        """Shortcut for message.encrypt().sign(skey_seed).hashcash()."""
        self.encrypt().sign(skey_seed)
        if difficulty:
            return self.hashcash(difficulty)
        return self.hashcash()

    def pack(self) -> bytes:
        """Pack the data with struct."""
        fstr = '!32s32sii64s' + str(len(self.body)) + 's'
        return struct.pack(fstr, self.dst, self.src, self.ts, self.nonce, self.sig, self.body)

    @classmethod
    def unpack(cls, packed: bytes) -> Message:
        """Unpack the data with struct."""
        fstr = '!32s32sii64s' + str(len(packed) - 136) + 's'
        (dst, src, ts, nonce, sig, body) = struct.unpack(fstr, packed)
        return Message(src, dst, body, ts, nonce, sig)

    def sign(self, skey_seed: bytes) -> Message:
        """Generate a signature for the message."""
        self.sig = self.crypto_adapter.sign(bytes(self), skey_seed)
        return self

    def verify(self) -> bool:
        """Verify the message signature."""
        if self.sig is None:
            return False
        return self.crypto_adapter.verify(self.sig, bytes(self), self.src)

    def encrypt(self) -> Message:
        """Encrypt using ephemeral ECDHE."""
        self.body = self.crypto_adapter.encrypt(self.body, self.dst)
        return self

    def decrypt(self, skey_seed: bytes) -> Message:
        """Decrypt using ephemeral ECDHE."""
        if type(skey_seed) is not bytes:
            raise TypeError('skey_seed must be bytes')
        if len(skey_seed) != 32:
            raise ValueError('skey_seed must be 32 bytes')

        self.body = self.crypto_adapter.decrypt(self.body, skey_seed)
        return self


class Content(AbstractContent):
    @classmethod
    def from_content(cls, content: bytes) -> Content:
        if type(content) is not bytes:
            raise TypeError('content must be bytes')

        id = sha256(content).digest()
        return cls(id, content)

    def pack(self) -> bytes:
        fstr = '!32s' + str(len(self.content)) + 's'
        return struct.pack(fstr, self.id, self.content)

    @classmethod
    def unpack(cls, packed: bytes) -> Content:
        fstr = '!32s' + str(len(packed) - 32) + 's'
        (id, content) = struct.unpack(fstr, packed)
        return cls(id, content)


class Topic(AbstractTopic):
    @classmethod
    def from_descriptor(cls, descriptor: bytes) -> Topic:
        if type(descriptor) is not bytes:
            raise TypeError("descriptor must be bytes")

        id = sha256(descriptor).digest()
        return cls(id, descriptor)


class Bulletin(AbstractBulletin):
    def __init__(self, topic: AbstractTopic, content: AbstractContent,
                ts: int = None, nonce: int = None) -> None:
        if not isinstance(topic, AbstractTopic):
            raise TypeError("topic must implement AbstractTopic")
        if not isinstance(content, AbstractContent):
            raise TypeError("content must implement AbstractContent")

        self.topic = topic
        self.content = content
        self.ts = ts or int(time())
        self.nonce = nonce or randint(0, 2**16-1)

    def __bytes__(self) -> bytes:
        return self.pack()

    def check_hash(self) -> bool:
        """Check that the hash of a message meets the difficulty threshold."""
        digest = tapehash1(self.get_header(), TAPEHASH_CODE_SIZE)
        return check_bulletin_difficulty(digest)

    def hashcash(self) -> Bulletin:
        """Increment the nonce until check_hash() returns True."""
        while (not self.check_hash()):
            self.nonce = (self.nonce + 1) % 2**32
        return self

    def pack(self) -> bytes:
        fstr = '!32s32sii' + str(len(self.content.content)) + 's'
        return struct.pack(
            fstr,
            self.topic.id,
            self.content.id,
            self.ts,
            self.nonce,
            self.content.content
        )

    @classmethod
    def unpack(cls, data: bytes) -> Bulletin:
        fstr = '!32s32sii' + str(len(data) - 72) + 's'
        topic_id, content_id, ts, nonce, content = struct.unpack(fstr, data)
        return cls(Topic(topic_id), Content(content_id, content), ts, nonce)


class Node(AbstractNode):
    def __init__(self, address: bytes, delivery_code: bytes = None) -> None:
        """Create a node from its address (public key bytes)."""
        # set defaults
        super().__init__(address, delivery_code=delivery_code)

        # set delivery_code if necessary
        if self.delivery_code is None:
            self.delivery_code = token_bytes(8)

        # subscribe the node to messages directed to itself and the beacon channel
        self.topics_followed = set([
            Topic.from_descriptor(self.delivery_code + self.address),
            Topic.from_descriptor(b'node beacon channel')
        ])

    @classmethod
    def from_seed(cls, seed: bytes, delivery_code: bytes = None) -> Node:
        """Create a node from a seed filling out _skey."""
        node = cls(NaclAdapter().get_address_from_seed(seed), delivery_code=delivery_code)
        node._seed = seed
        return node

    def __lt__(self, other: Node) -> bool:
        return self.address < other.address

    def __repr__(self) -> str:
        if self._seed is not None:
            return "{'address': '" + format_address(self.address) + "','seed':'" + self._seed.hex() + "}"
        else:
            return "{'address': '" + format_address(self.address) + "'}"

    def update_delivery_code(self) -> Node:
        """Change delivery code, change topic subscriptions, and queue
            action to update peers/friends.
        """
        self.unsubscribe(Topic.from_descriptor(self.delivery_code + self.address))
        old_code = self.delivery_code
        new_code = token_bytes(8)
        self.delivery_code = new_code
        self.subscribe(Topic.from_descriptor(self.delivery_code + self.address))
        self.queue_action(Action('notify_changed_delivery_code', {
            'old_code': old_code,
            'new_code': new_code
        }))
        return self

    def register_message_sender(self, sender: SupportsSendMessage) -> Node:
        """Register the message sender."""
        if not isinstance(sender, SupportsSendMessage):
            raise TypeError('sender must fulfill SupportsSendMessage duck type')

        self._message_sender = sender
        return self

    def register_message_handler(self, handler: SupportsHandleMessage) -> Node:
        """Register the incoming message handler."""
        if not isinstance(handler, SupportsHandleMessage):
            raise TypeError('handler must fulfill SupportsHandleMessage duck type')

        self._message_handler = handler
        return self

    def register_action_handler(self, handler: SupportsHandleAction) -> None:
        """Register the action handler."""
        if not isinstance(handler, SupportsHandleAction):
            raise TypeError('handler must fulfill SupportsHandleAction duck type')

        self._action_handler = handler
        return self

    def register_bulletin_handler(self, handler: SupportsHandleRetrieveListQueryBulletin) -> None:
        """Register the bulletin handler."""
        if not isinstance(handler, SupportsHandleRetrieveListQueryBulletin):
            raise TypeError('handler must fulfill SupportsHandleRetrieveListQueryBulletin duck type')

        self._bulletin_handler = handler
        return self

    def add_connection(self, connection: AbstractConnection) -> Node:
        """Add the specified connection and set its difficulty."""
        if not isinstance(connection, AbstractConnection):
            raise TypeError('connection must implement AbstractConnection')

        if 'difficulty' in connection.data:
            connection.data['difficulty'] = connection.data['difficulty']
        else:
            connection.data['difficulty'] = MESSAGE_DIFFICULTY

        self.connections.add(connection)
        return self

    def drop_connection(self, connection: AbstractConnection) -> Node:
        """Drop the specified connection."""
        if not isinstance(connection, AbstractConnection):
            raise TypeError('connection must implement AbstractConnection')

        self.connections.remove(connection)
        return self

    def count_connections(self) -> int:
        return len(self.connections)

    def receive_message(self, message: AbstractMessage) -> None:
        """Queue up an incoming message if its signature is valid or
            ignored.
        """
        if not isinstance(message, AbstractMessage):
            raise TypeError('message must implement AbstractMessage')

        global MESSAGE_TTL

        if message.dst != self.address:
            debug("Node.receive_message: message dropped for improper destination")
        elif int(time()) > (message.ts + MESSAGE_TTL):
            debug("Node.receive_message: old message discarded")
        elif not message.check_hash():
            debug("Node.receive_message: message failed hashcash check")
        elif message.sig is not None:
            if message.verify():
                try:
                    message.decrypt(self._seed)
                    self._inbound.put(message)
                except CryptoError:
                    debug("Node.receive_message: message dropped due to CryptoError")
            else:
                debug("Node.receive_message: message signature failed verification")
        else:
            debug("Node.receive_message: unsigned message rejected")

    def get_message_difficulty(self, destination: bytes) -> int:
        for c in self.connections:
            if destination in [n.address for n in c.nodes]:
                return c.data['difficulty']
        return MESSAGE_DIFFICULTY

    def send_message(self, dst: bytes, msg: bytes) -> Node:
        """Queue up an outgoing message."""
        if type(dst) is not bytes:
            raise TypeError("dst must be bytes")
        if type(msg) is not bytes:
            raise TypeError("msg must be bytes")
        if self._seed is None:
            raise ValueError("Cannot send a message without a seed set.")

        message = Message(self.address, dst, msg)
        difficulty = self.get_message_difficulty(dst)
        message.prepare_for_send(self._seed, difficulty)

        if len(self.connections):
            if len([c for c in self.connections if dst in [n.address for n in c.nodes]]):
                self._outbound.put(message)
            else:
                debug("cannot deliver message due to lack of connection")
        else:
            self._outbound.put(message)

        return self

    def subscribe(self, topic: AbstractTopic) -> Node:
        if not isinstance(topic, AbstractTopic):
            raise TypeError('topic must implement AbstractTopic')

        self.topics_followed.add(topic)
        return self

    def unsubscribe(self, topic: AbstractTopic) -> Node:
        if topic in self.topics_followed:
            self.topics_followed.remove(topic)

        return self

    def publish(self, bulletin: AbstractBulletin) -> Node:
        """Publish a bulletin by engaging the store_and_forward action."""
        message = Message(self.address, self.address, bytes(bulletin))
        message.encrypt().hashcash().sign(self._seed)
        self.receive_message(message)
        return self

    def queue_action(self, act: AbstractAction) -> Node:
        """Queue an action to be processed by the action handler."""
        if not isinstance(act, AbstractAction):
            raise TypeError('act must implement AbstractAction')

        self._actions.put(act)
        return self

    def process(self) -> Node:
        """Process actions for this node once."""
        if self._outbound.qsize() > 0 and self._message_sender is not None:
            self._message_sender.send(self._outbound.get())
        if self._inbound.qsize() > 0 and self._message_handler is not None:
            self._message_handler.handle(self._inbound.get())
        if self._actions.qsize() > 0 and self._action_handler is not None:
            self._action_handler.handle(self._actions.get())
        if self._new_bulletins.qsize() > 0 and self._bulletin_handler is not None:
            self._bulletin_handler.handle(self._new_bulletins.get())

        return self

    def action_count(self) -> int:
        """Count the size of pending messages and actions."""
        return self._outbound.qsize() + self._inbound.qsize() + \
            self._actions.qsize() + self._new_bulletins.qsize()


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
        if type(name) is not str:
            raise TypeError('name must be str')
        if type(data) is not dict:
            raise TypeError('data must be dict')

        self.name = name
        self.data = data


class Connection(AbstractConnection):
    """Connection model represent an edge connecting two Nodes together."""
    def __init__(self, nodes: list[AbstractNode]) -> None:
        if type(nodes) not in (list, set):
            raise TypeError('nodes must be list or set')
        if len(nodes) != 2:
            raise ValueError('a Connection must connect exactly 2 nodes')
        for n in nodes:
            if not isinstance(n, AbstractNode):
                raise TypeError('each node must implement AbstractNode')

        self.nodes = set(nodes) if type(nodes) is list else nodes
        self.data = {}
