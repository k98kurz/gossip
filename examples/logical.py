from __future__ import annotations
from dataclasses import dataclass, field
from functools import reduce
from random import randint
from secrets import token_bytes
import readline

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from gossip.classes import (
    Action,
    Bulletin,
    Connection,
    Content,
    Message,
    Node,
    Topic,
)
from gossip.interfaces import (
    SupportsHandleAction,
    SupportsHandleMessage,
    SupportsHandleRetrieveListQueryBulletin,
    SupportsSendMessage,
)
from gossip.misc import (
    debug,
    format_address,
    set_difficulty,
    toggle_debug,
    toggle_short_address,
)


@dataclass
class ActionHandler(SupportsHandleAction):
    node: Node

    def handle(self, action: Action) -> None:
        if action.name == 'store_and_forward':
            self.store_and_forward(action)

    def store_and_forward(self, action: Action) -> None:
        if action.data['bulletin'] not in self.node.content_seen:
            # store
            self.node.mark_as_seen(action.data['bulletin'])
            debug(f"ActionHandler.handle(): store_and_forward [{format_address(action.data['bulletin'].content.id)}]")

            if len(self.node.connections) == 0:
                debug("ActionHandler.handle(): cannot forward - no peers connected")

            # forward
            for c in self.node.connections:
                dst = [n for n in c.nodes if n.address != self.node.address][0]
                self.node.send_message(dst.address, bytes(action.data['bulletin']))
        else:
            debug(f"ActionHandler.handle(): store_and_forward skipped for seen message")


@dataclass
class BulletinHandler(SupportsHandleRetrieveListQueryBulletin):
    node: Node
    topic_handlers: dict = field(default_factory=dict)
    bulletins: dict = field(default_factory=dict)

    def register_topic_handler(self, topic: Topic, handler: callable) -> BulletinHandler:
        if not isinstance(topic, Topic):
            raise TypeError('topic must be a Topic')
        if not callable(handler):
            raise TypeError('handler must be callable')

        self.topic_handlers[topic.id] = handler
        return self

    def handle(self, bulletin: Bulletin) -> None:
        if bulletin.topic.id in [t.id for t in self.node.topics_followed]:
            if bulletin.topic.id not in self.bulletins:
                self.bulletins[bulletin.topic.id] = set([bulletin])
            else:
                self.bulletins[bulletin.topic.id].add(bulletin)

            if bulletin.topic.id in self.topic_handlers:
                self.topic_handlers[bulletin.topic.id](bulletin)
            else:
                debug(f"BulletinHandler.handle(): no topic handler assigned for topic.id {format_address(bulletin.topic.id)}")
        else:
            debug(f"BulletinHandler.handle(): node is not subscribed to topic {format_address(bulletin.topic.id)}")

    def retrieve(self, topic_id: bytes, content_id: bytes) -> Bulletin:
        if topic_id in self.bulletins:
            if content_id in [b.content.id for b in self.bulletins[topic_id]]:
                return [b for b in self.bulletins[topic_id] if b.content.id == content_id][0]
        return None

    def list(self, topic_id: bytes) -> list[bytes]:
        if topic_id in self.bulletins:
            return [b.content.id for b in self.bulletins[topic_id]]
        return []

    def query(self, query: dict) -> set[Bulletin]:
        if type(query) is not dict:
            raise TypeError('query must be a dict')

        bulletins = [b for topic in [self.bulletins[tid] for tid in self.bulletins] for b in topic]

        # exact match
        if '=' in query:
            if 'topic_id' in query['=']:
                bulletins = [b for b in bulletins if b.topic.id == query['=']['topic_id']]
            if 'content_id' in query['=']:
                bulletins = [b for b in bulletins if b.content.id == query['=']['content_id']]
            if 'content' in query['=']:
                bulletins = [b for b in bulletins if b.content.content == query['=']['content']]

        # starts with
        if '^' in query:
            if 'topic_id' in query['^']:
                length = len(query['^']['topic_id'])
                bulletins = [b for b in bulletins if b.topic.id[:length] == query['^']['topic_id']]
            if 'content_id' in query['^']:
                length = len(query['^']['content_id'])
                bulletins = [b for b in bulletins if b.content.id[:length] == query['^']['content_id']]
            if 'content' in query['^']:
                length = len(query['^']['content'])
                bulletins = [b for b in bulletins if b.content.content[:length] == query['^']['content']]

        # ends with
        if '$' in query:
            if 'topic_id' in query['$']:
                length = len(query['$']['topic_id'])
                bulletins = [b for b in bulletins if b.topic.id[:-length] == query['$']['topic_id']]
            if 'content_id' in query['$']:
                length = len(query['$']['content_id'])
                bulletins = [b for b in bulletins if b.content.id[:-length] == query['$']['content_id']]
            if 'content' in query['$']:
                length = len(query['$']['content'])
                bulletins = [b for b in bulletins if b.content.content[:-length] == query['$']['content']]

        return set(bulletins)


@dataclass
class MessageHandler(SupportsHandleMessage):
    node: Node

    def handle(self, msg: Message) -> None:
        debug(f'MessageHandler.handle(): {format_address(bytes(msg.body))}')
        bulletin = Bulletin.unpack(msg.body)
        self.node.queue_action(Action('store_and_forward', {'bulletin': bulletin}))


@dataclass
class MessageSender(SupportsSendMessage):
    node: Node

    def send(self, msg: Message) -> None:
        nodes = set()
        for c in self.node.connections:
            nodes = nodes.union(c.nodes)

        if msg.dst in [n.address for n in nodes]:
            destination = [n for n in nodes if n.address == msg.dst][0]
            destination.receive_message(msg)


def run_tick(nodes: list[Node]):
    for n in nodes:
        n.process()


def action_count(nodes: list[Node]):
    return reduce(lambda c, n: c + n.action_count(), nodes, 0)


def main(node_count: int):
    # setup
    set_difficulty(1) # just for demonstration purposes
    topic = Topic.from_descriptor(b'test channel')
    topic_handler = lambda bulletin: debug(f'topic handler invoked for {format_address(bulletin.topic.id)}.{format_address(bulletin.content.id)}')
    nodes = [Node.from_seed(token_bytes(32)) for i in range(node_count)]
    for node in nodes:
        node.register_action_handler(ActionHandler(node))
        node.register_bulletin_handler(BulletinHandler(node).register_topic_handler(topic, topic_handler))
        node.register_message_handler(MessageHandler(node))
        node.register_message_sender(MessageSender(node))
        node.subscribe(topic)

    # flag
    end_signal = False

    while not end_signal:
        data = input("$: ")
        command = data.split(' ')[0].strip()
        data = ' '.join(data.split(' ')[1:]).strip()

        if command in ('quit', 'q'):
            end_signal = True
        elif command in ('list', 'nodes', 'l', 'n', 'ln'):
            for n in nodes:
                print(f"{format_address(n.address)}: {[format_address(b.content.id) for b in n.content_seen]}")
        elif command in ('listcon', 'connections', 'lc'):
            connections = set()
            for n in nodes:
                connections = connections.union(n.connections)
            for c in connections:
                cnodes = list(c.nodes)
                print(f"{format_address(cnodes[0].address)} - {format_address(cnodes[1].address)}")
        elif command in ('c', 'connect'):
            for n in nodes:
                others = [o for o in nodes if o is not n]
                for i in range(3):
                    o = others[randint(0, len(others)-1)]
                    n.add_connection(Connection([n, o]))
                    o.add_connection(Connection([n, o]))
        elif command in ('message', 'm'):
            src = nodes[randint(0, len(nodes)-1)]
            bulletin = Bulletin(topic, Content.from_content(bytes(data, 'utf-8')))
            src.queue_action(Action('store_and_forward', {'bulletin': bulletin}))
        elif command in ('d', 'debug'):
            print("debug enabled" if toggle_debug() else "debug disabled")
        elif command in ('s', 'short'):
            print("short addresses enabled" if toggle_short_address() else "short addresses disabled")
        elif command in ('r', 'run'):
            while action_count(nodes) > 0:
                run_tick(nodes)
        elif command in ('h', 'help', '?'):
            print("options:\t[l|ln|nodes|list] to list nodes and messages seen by each")
            print("\t\t[m|message] {str} to send a message")
            print("\t\t[c|connect] to connect nodes together randomly")
            print("\t\t[lc|listcon|connections] list all connections")
            print("\t\t[q|quit] to end")
            print("\t\t[h|help|?] display this text")
            print("\t\t[d|debug] to toggle debug messages")
            print("\t\t[s|short] to toggle displaying short address format")
            print("\t\t[r|run] to run until no pending actions remain")
            print("\t\tanything else to process a tick")
        else:
            run_tick(nodes)


if __name__ == '__main__':
    node_count = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    main(node_count)
