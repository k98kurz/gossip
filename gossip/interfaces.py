from __future__ import annotations
from abc import ABC, abstractclassmethod, abstractmethod
from dataclasses import dataclass, field
from random import randint
from time import time
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from queue import SimpleQueue
from typing import Protocol


class SupportsSendMessage(Protocol):
    """Duck type protocol for message sender."""
    def send(self, msg: AbstractMessage) -> None:
        ...


class SupportsHandleMessage(Protocol):
    """Duck type protocol for incoming message handler."""
    def handle(self, msg: AbstractMessage) -> None:
        ...


class SupportsHandleAction(Protocol):
    """Duck type protocol for action handler."""
    def handle(self, action: AbstractAction) -> None:
        ...

    def store_and_forward(self, action: AbstractAction) -> None:
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
    def check_hash(self, target: int) -> bool:
        pass

    @abstractmethod
    def pow(self) -> None:
        pass

    @abstractmethod
    def find_nonce(self, target: int) -> None:
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
    def encrypt(self) -> None:
        pass

    @abstractmethod
    def decrypt(self, skey: SigningKey) -> None:
        pass


@dataclass
class AbstractConnection(ABC):
    nodes: set[AbstractNode]
    data: dict = field(default_factory=dict)

    @abstractmethod
    def __hash__(self) -> int:
        pass


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
    content: bytes

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass

    @abstractmethod
    def __hash__(self) -> int:
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
    msgs_seen: set[bytes]
    bulletins: set[AbstractBulletin]
    topics_followed: set[bytes]
    connections: set[AbstractConnection]
    data: dict
    _seed: bytes
    _skey: SigningKey
    _vkey: VerifyKey
    _inbound: SimpleQueue
    _outbound: SimpleQueue
    _actions: SimpleQueue
    _message_sender: SupportsSendMessage
    _message_handler: SupportsHandleMessage
    _action_handler: SupportsHandleAction

    @abstractmethod
    def __init__(self, address: bytes) -> None:
        self.address = address
        pass

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
    def register_message_sender(self, sndr: SupportsSendMessage) -> None:
        pass

    @abstractmethod
    def register_message_handler(self, hndlr: SupportsHandleMessage) -> None:
        pass

    @abstractmethod
    def register_action_handler(self, hndlr: SupportsHandleAction) -> None:
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
    def subscribe(self, topic: bytes) -> None:
        pass

    @abstractmethod
    def unsubscribe(self, topic: bytes) -> None:
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
