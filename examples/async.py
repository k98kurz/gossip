from __future__ import annotations
import asyncio
from logical import (
    ActionHandler,
    BulletinHandler,
    MessageHandler,
    MessageSender,
    Action,
    Bulletin,
    Connection,
    Content,
    Node,
    Topic,
    debug,
    format_address,
    set_difficulty,
    toggle_debug,
    toggle_short_address,
)
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession
from random import randint
from secrets import token_bytes
from sys import argv


"""Logic-only example of how a network of nodes pass messages/bulletins
    between each other. Runs asynchronously. Reuses most code from the
    synchronous example in logical.py.
"""


async def run_ticks(nodes: list[Node]):
    while True:
        for n in nodes:
            if n.action_count() > 0:
                n.process()
        await asyncio.sleep(1)


async def interactive_shell(nodes: list[Node], topic: Topic):
    # create prompt
    session = PromptSession("$: ")

    # flag
    end_signal = False

    while not end_signal:
        try:
            data = await session.prompt_async()
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
            elif command in ('h', 'help', '?'):
                print("options:\t[l|ln|nodes|list] to list nodes and messages seen by each")
                print("\t\t[m|message] {str} to send a message")
                print("\t\t[c|connect] to connect nodes together randomly")
                print("\t\t[lc|listcon|connections] list all connections")
                print("\t\t[q|quit] to end")
                print("\t\t[h|help|?] display this text")
                print("\t\t[d|debug] to toggle debug messages")
                print("\t\t[s|short] to toggle displaying short address format")
        except (EOFError, KeyboardInterrupt):
            return


async def main(node_count: int):
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

    with patch_stdout():
        task = asyncio.create_task(run_ticks(nodes))
        await interactive_shell(nodes, topic)


if __name__ == '__main__':
    node_count = int(argv[1]) if len(argv) > 1 else 16
    asyncio.run(main(node_count))
