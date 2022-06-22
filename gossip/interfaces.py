from __future__ import annotations
from abc import ABC, ABCMeta, abstractclassmethod, abstractmethod
from dataclasses import dataclass, field
from gossip.misc import CONTENT_TTL
from random import randint
from time import time
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from queue import SimpleQueue
from typing import Protocol, runtime_checkable


@runtime_checkable
class SupportsSendMessage(Protocol):
    """Duck type protocol for message sender."""
    def send(self, msg: AbstractMessage) -> None:
        ...


@runtime_checkable
class SupportsHandleMessage(Protocol):
    """Duck type protocol for incoming message handler."""
    def handle(self, msg: AbstractMessage) -> None:
        ...


@runtime_checkable
class SupportsHandleAction(Protocol):
    """Duck type protocol for action handler."""
    def handle(self, action: AbstractAction) -> None:
        ...

    def store_and_forward(self, action: AbstractAction) -> None:
        ...


@runtime_checkable
class SupportsHandleRetrieveListQueryBulletin(Protocol):
    """Duck type protocol for handling bulletins of subscribed topics."""
    def handle(self, bulletin: AbstractBulletin) -> None:
        ...

    def retrieve(self, topic_id: bytes, content_id: bytes) -> AbstractBulletin:
        ...

    def list(self, topic_id: bytes) -> list[bytes]:
        ...

    def query(self, query: dict) -> set[AbstractBulletin]:
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
    def sign(self, skey: SigningKey) -> SignedMessage:
        pass

    @abstractmethod
    def verify(self) -> bool:
        pass

    @abstractmethod
    def encrypt(self) -> AbstractMessage:
        pass

    @abstractmethod
    def decrypt(self, skey: SigningKey) -> AbstractMessage:
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
    content_seen: set[AbstractBulletin] = field(default_factory=set)
    topics_followed: set[AbstractTopic] = field(default_factory=set)
    connections: set[AbstractConnection] = field(default_factory=set)
    data: dict = field(default_factory=dict)
    _seed: bytes = None
    _skey: SigningKey = None
    _vkey: VerifyKey = None
    _inbound: SimpleQueue = field(default_factory=SimpleQueue)
    _outbound: SimpleQueue = field(default_factory=SimpleQueue)
    _new_bulletins: SimpleQueue = field(default_factory=SimpleQueue)
    _actions: SimpleQueue = field(default_factory=SimpleQueue)
    _message_sender: SupportsSendMessage = None
    _message_handler: SupportsHandleMessage = None
    _action_handler: SupportsHandleAction = None
    _bulletin_handler: SupportsHandleRetrieveListQueryBulletin = None

    @abstractclassmethod
    def from_seed(cls, seed: bytes) -> AbstractNode:
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
    def register_message_sender(self, sender: SupportsSendMessage) -> None:
        pass

    @abstractmethod
    def register_message_handler(self, handler: SupportsHandleMessage) -> None:
        pass

    @abstractmethod
    def register_action_handler(self, handler: SupportsHandleAction) -> None:
        pass

    @abstractmethod
    def register_bulletin_handler(self, handler: SupportsHandleRetrieveListQueryBulletin) -> None:
        pass

    @abstractmethod
    def add_connection(self, connection: AbstractConnection) -> None:
        pass

    @abstractmethod
    def drop_connection(self, connection: AbstractConnection) -> None:
        pass

    @abstractmethod
    def count_connections(self) -> int:
        pass

    @abstractmethod
    def receive_message(self, message: AbstractMessage):
        pass

    @abstractmethod
    def send_message(self, dst: bytes, msg: bytes) -> None:
        pass

    @abstractmethod
    def subscribe(self, topic: AbstractTopic) -> None:
        pass

    @abstractmethod
    def unsubscribe(self, topic: AbstractTopic) -> None:
        pass

    @abstractmethod
    def publish(self, bulletin: AbstractBulletin) -> None:
        pass

    @abstractmethod
    def queue_action(self, act: AbstractAction) -> None:
        pass

    @abstractmethod
    def process(self) -> None:
        pass

    @abstractmethod
    def action_count(self) -> int:
        pass

    def mark_as_seen(self, bulletin: AbstractBulletin) -> None:
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
