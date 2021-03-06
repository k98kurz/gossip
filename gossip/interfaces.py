from __future__ import annotations
from abc import ABC, abstractclassmethod, abstractmethod
from dataclasses import dataclass, field
from gossip.misc import CONTENT_TTL
from queue import SimpleQueue
from random import randint
from secrets import token_bytes
from time import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class SupportsSendMessage(Protocol):
    """Duck type protocol for message sender."""
    def send(self, msg: AbstractMessage) -> SupportsSendMessage:
        ...


@runtime_checkable
class SupportsHandleMessage(Protocol):
    """Duck type protocol for incoming message handler."""
    def handle(self, msg: AbstractMessage) -> SupportsHandleMessage:
        ...


@runtime_checkable
class SupportsHandleAction(Protocol):
    """Duck type protocol for action handler."""
    def handle(self, action: AbstractAction) -> SupportsHandleAction:
        ...

    def store_and_forward(self, action: AbstractAction) -> None:
        ...


@runtime_checkable
class SupportsHandleRetrieveListQueryBulletin(Protocol):
    """Duck type protocol for handling bulletins of subscribed topics."""
    def handle(self, bulletin: AbstractBulletin) -> SupportsHandleRetrieveListQueryBulletin:
        ...

    def retrieve(self, topic_id: bytes, content_id: bytes) -> AbstractBulletin | None:
        ...

    def list(self, topic_id: bytes) -> list[bytes]:
        ...

    def query(self, query: dict) -> set[AbstractBulletin]:
        ...


@runtime_checkable
class CryptoAdapter(Protocol):
    """Duck type protocol for handling cryptographic operations."""
    def get_address_from_seed(self, seed: bytes) -> bytes:
        ...

    def encrypt(self, plaintext: bytes, address: bytes) -> bytes:
        ...

    def decrypt(self, ciphertext: bytes, skey_seed: bytes) -> bytes:
        ...

    def sign(self, message: bytes, skey_seed: bytes) -> bytes:
        ...

    def verify(self, signature: bytes, message: bytes, vkey: bytes) -> bool:
        ...


class CryptoError(BaseException):
    ...


@dataclass
class AbstractMessage(ABC):
    src: bytes
    dst: bytes
    body: bytes
    ts: int = field(default_factory=lambda: int(time()))
    nonce: int = field(default_factory=lambda: randint(0, 2**16-1))
    sig: bytes = None
    metadata: dict = field(default_factory=dict)
    crypto_adapter: CryptoAdapter = field(default=None)

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass

    @abstractmethod
    def __hash__(self) -> int:
        pass

    @abstractmethod
    def get_header(self) -> bytes:
        pass

    @abstractmethod
    def check_hash(self) -> bool:
        pass

    @abstractmethod
    def hashcash(self) -> AbstractMessage:
        pass

    @abstractmethod
    def pack(self) -> bytes:
        pass

    @abstractclassmethod
    def unpack(cls, packed: bytes) -> AbstractMessage:
        pass

    @abstractmethod
    def sign(self, skey_seed: bytes) -> AbstractMessage:
        pass

    @abstractmethod
    def verify(self) -> bool:
        pass

    @abstractmethod
    def encrypt(self) -> AbstractMessage:
        pass

    @abstractmethod
    def decrypt(self, skey_seed: bytes) -> AbstractMessage:
        pass


@dataclass
class AbstractContent(ABC):
    id: bytes
    content: bytes = None

    def __hash__(self) -> int:
        return hash(self.id)

    def __bytes__(self) -> bytes:
        return self.id + self.content

    def __repr__(self) -> str:
        if self.content is None:
            return self.id.hex()
        else:
            return self.id.hex() + ':' + self.content.hex()

    @abstractmethod
    def pack(self) -> bytes:
        pass

    @abstractclassmethod
    def unpack(cls, packed: bytes) -> AbstractContent:
        pass

    @abstractclassmethod
    def from_content(cls, content: bytes) -> AbstractContent:
        pass


@dataclass
class AbstractConnection(ABC):
    nodes: set[AbstractNode]
    data: dict = field(default_factory=dict)

    def __hash__(self) -> int:
        """Enable inclusion in sets."""
        node_list = list(self.nodes)
        node_list.sort()
        return hash(node_list[0].address + node_list[1].address)


@dataclass
class AbstractAction(ABC):
    name: str
    data: dict


@dataclass
class AbstractTopic(ABC):
    id: bytes
    descriptor: bytes = None

    def __hash__(self) -> int:
        return hash(self.id)

    def __bytes__(self) -> bytes:
        return self.id

    def __repr__(self) -> str:
        if self.descriptor is not None:
            return self.id.hex() + ' (' + self.descriptor.hex() + ')'
        else:
            return self.id.hex()

    @abstractclassmethod
    def from_descriptor(cls, descriptor: bytes) -> AbstractTopic:
        pass


@dataclass
class AbstractBulletin(ABC):
    topic: AbstractTopic
    content: AbstractContent
    ts: int = field(default_factory=lambda: int(time()))
    nonce: int = field(default_factory=lambda: randint(0, 2**16-1))

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass

    def __hash__(self) -> int:
        return hash(self.get_header())

    def __eq__(self, other: AbstractBulletin) -> bool:
        return hash(self) == hash(other)

    def get_header(self) -> bytes:
        return self.topic.id + self.content.id + self.ts.to_bytes(4, 'big') + self.nonce.to_bytes(4, 'big')

    def expired(self) -> bool:
        return time() >= self.ts + CONTENT_TTL

    @abstractmethod
    def check_hash(self) -> bool:
        pass

    @abstractmethod
    def hashcash(self) -> AbstractBulletin:
        pass

    @abstractmethod
    def pack(self) -> bytes:
        pass

    @abstractclassmethod
    def unpack(cls, data: bytes) -> AbstractBulletin:
        pass


@dataclass
class AbstractNode(ABC):
    address: bytes
    delivery_code: bytes = field(default_factory=lambda: token_bytes(8))
    content_seen: set[AbstractBulletin] = field(default_factory=set)
    topics_followed: set[AbstractTopic] = field(default_factory=set)
    connections: set[AbstractConnection] = field(default_factory=set)
    data: dict = field(default_factory=dict)
    _seed: bytes = None
    _inbound: SimpleQueue = field(default_factory=SimpleQueue)
    _outbound: SimpleQueue = field(default_factory=SimpleQueue)
    _new_bulletins: SimpleQueue = field(default_factory=SimpleQueue)
    _actions: SimpleQueue = field(default_factory=SimpleQueue)
    _message_sender: SupportsSendMessage = None
    _message_handler: SupportsHandleMessage = None
    _action_handler: SupportsHandleAction = None
    _bulletin_handler: SupportsHandleRetrieveListQueryBulletin = None

    @abstractclassmethod
    def from_seed(cls, seed: bytes, delivery_code: bytes = None) -> AbstractNode:
        pass

    def __hash__(self) -> int:
        """Enable inclusion in sets."""
        return hash(self.address)

    @abstractmethod
    def __lt__(self, other: AbstractNode) -> bool:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def update_delivery_code(self) -> AbstractNode:
        """Change delivery code, change topic subscriptions, and update
            peers/friends.
        """
        pass

    @abstractmethod
    def register_message_sender(self, sender: SupportsSendMessage) -> AbstractNode:
        pass

    @abstractmethod
    def register_message_handler(self, handler: SupportsHandleMessage) -> AbstractNode:
        pass

    @abstractmethod
    def register_action_handler(self, handler: SupportsHandleAction) -> AbstractNode:
        pass

    @abstractmethod
    def register_bulletin_handler(self, handler: SupportsHandleRetrieveListQueryBulletin) -> AbstractNode:
        pass

    @abstractmethod
    def add_connection(self, connection: AbstractConnection) -> AbstractNode:
        pass

    @abstractmethod
    def drop_connection(self, connection: AbstractConnection) -> AbstractNode:
        pass

    @abstractmethod
    def count_connections(self) -> int:
        pass

    @abstractmethod
    def receive_message(self, message: AbstractMessage):
        pass

    @abstractmethod
    def send_message(self, dst: bytes, msg: bytes) -> AbstractNode:
        pass

    @abstractmethod
    def subscribe(self, topic: AbstractTopic) -> AbstractNode:
        pass

    @abstractmethod
    def unsubscribe(self, topic: AbstractTopic) -> AbstractNode:
        pass

    @abstractmethod
    def publish(self, bulletin: AbstractBulletin) -> AbstractNode:
        pass

    @abstractmethod
    def queue_action(self, act: AbstractAction) -> AbstractNode:
        pass

    @abstractmethod
    def process(self) -> AbstractNode:
        pass

    @abstractmethod
    def action_count(self) -> int:
        pass

    def mark_as_seen(self, bulletin: AbstractBulletin) -> AbstractNode:
        if not isinstance(bulletin, AbstractBulletin):
            raise TypeError('bulletin must implement AbstractBulletin')

        self.content_seen.add(bulletin)
        self._new_bulletins.put(bulletin)

    def delete_old_content(self) -> int:
        to_delete = set()
        for b in self.content_seen:
            if b.expired():
                to_delete.add(b)

        self.content_seen = self.content_seen.difference(to_delete)
        return len(to_delete)
