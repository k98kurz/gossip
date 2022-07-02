# Gossip

This module uses ed25519, x25519, sha256, and shake256 to implement a
gossip protocol for passing messages between connected nodes. It can
also be easily extended for delivering messages in a routed network, for
example using greedy embeddings constructed with spanning trees.

## Overview

The general idea is that nodes communicate over connections (or send
messages in a connectionless setting), with each message being encrypted
for privacy and signed to prove authenticity; all unsigned messages are
dropped. Additionally, hashcash using a custom tapehash digest system is
used as an anti-spam measure; any message encountered that does not meet
the difficulty threshold is dropped. A 4-byte integer nonce is included
and incremented until the difficulty threshold is met.

When a valid message is received, it is added to the inbound message
queue to be handled by the registered message handler. When an action is
queued up by the message handler, it is added to the actions queue to be
handled by the action handler. When the node wishes to send a message,
it is added to the outbound queue to be handled by the registered
message sender. All handlers are invoked when `process()` is called,
starting with the message sender, then the message handler, then the
action handler, and finally the bulletin handler. Each call to
`process()` will pop a single item off of each queue to be handled by
the relevant handler.

There is also a system of Topics and Bulletins. The first 72 bytes of a
Bulletin are the header composed of a 32 byte Topic id, a 32 byte
Content id, a 4-byte timestamp int, and a 4-byte nonce, with the
remainder being content. The timestamp and nonce are included for using
hashcash to prevent Bulletin spam: any Bulletin with an expired
timestamp or that fails hashcash verification will not be stored or
forwarded. A Topic id is the sha256 hash of the Topic descriptor bytes,
which can be generated by calling `Topic.from_descriptor`. A Node can
subscribe to any Topic, and the default subscriptions are the node
beacon channel and bulletins sent to the individual Node. A Node can
also unsubscribe from any Topic. The Content id is the sha256 hash of
the content bytes, which can be generated by calling
`Content.from_content`.

Directly connected Nodes can be represented with the Neighbor class.
These Neighbors can be used to keep track of the Topics that they have
expressed interest in, but this is optional.

An important note is that the registered action handler must at a
minimum include a `store_and_forward` function that calls `mark_as_seen`
on the Node to add the Bulletin to the `content_seen` set. Old content
can be purged by periodically calling the `delete_old_content` method on
the Node. It is also worthwhile to include `request_synchronization`,
`synchronize_to`, `synchronize_from`, `request_content`, and
`serve_content` functions in the action handler to ensure that nodes
synchronize recent bulletins. The `request_synchronization` action
should share subscribed Topics, and the `synchronize_to` action should
send Content ids of Bulletins for the requested Topics. All
communications between nodes should take the form of Bulletins wrapped
in Messages.

When `mark_as_seen` is called, it pushes the Bulletin onto the new
bulletins queue to be handled by the registered bulletin handler on the
next `process()` call. The bulletin handler is responsible for storage
and retrieval of bulletins via the `handle`, `retrieve`, `list`, and
`query` methods.

The code is reasonably SOLID and thoroughly tested.

## Status

- [x] Globals and miscellaneous functions + tests
- [x] Interfaces + tests
- [x] Basic Classes + tests
- [x] Abstract away PyNaCl Ed25519 coupling with adapter pattern
- [ ] Add anti-spam delivery code to nodes (for topic descriptor)
- [x] Refactor interfaces and classes to use monad pattern where possible
- [x] Example logical synchronous implementation
- [x] Example logical asynchronous implementation
- [ ] Example asynchronous implementation using sockets and sqlite

## Installation

Currently, this project is still in development, so the best way to install is
to clone the repo and then run the following from within the root directory
(assuming a Linix terminal):

```
python -m venv venv/
source venv/bin/activate
pip install -r requirements.txt
```

On Windows, you may have to run `source venv/Scripts/activate` instead
of `source venv/bin/activate`.

To run the examples, also run `pip install -r optional_requirements.txt`.

These instructions will change once development is complete and the module is
published as a package.

## Classes and Interfaces

### Interfaces

- SupportsSendMessage(Protocol)
- SupportsHandleMessage(Protocol)
- SupportsHandleAction(Protocol)
- SupportsHandleRetrieveListQueryBulletin(Protocol)
- AbstractMessage(ABC)
- AbstractContent(ABC)
- AbstractConnection(ABC)
- AbstractAction(ABC)
- AbstractTopic(ABC)
- AbstractBulletin(ABC)
- AbstractNode(ABC)

### Classes

- Message(AbstractMessage)
- Content(AbstractContent)
- Topic(AbstractTopic)
- Bulletin(AbstractBulletin)
- Node(AbstractNode)
- Neighbor(Node)
- Action(AbstractAction)
- Connection(AbstractConnection)

## Examples

Currently, only logical (no network stack) examples have been
implemented. Run the synchronous example with
`python examples/logical.py {n_nodes=16}`. Run the asynchronous example
with `python examples/async.py {n_nodes=16}`.

Type '?' and hit enter to get a list of available options for all
examples.

The code in `examples/logical.py` is reused in `examples/async.py`, with
the only difference being the inclusion of asyncio to demonstrate how an
implementation would function in an asynchronous setting. These examples
also demonstrate how op codes can be used to implement additional, non-
gossip protocol network actions, e.g. F2F routing overlays.

## Network Stack

There is currently no network stack implemented. An example network
stack using sockets and sqlite is the final unfinished task.

## Tests

Open a terminal in the root directory and run the following:

```
cd tests/
python -m unittest
```

## ISC License

Copyleft (c) 2022 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
