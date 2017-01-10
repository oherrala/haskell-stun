# Haskell STUN (Session Traversal Utilities for NAT) implementation

Protocol specifications:

STUN:

* [RFC5389](https://tools.ietf.org/html/rfc5389): Session Traversal Utilities for NAT (STUN)
* [RFC5780](https://tools.ietf.org/html/rfc5780): NAT Behavior Discovery Using Session Traversal Utilities for NAT (STUN)

TURN:

* [RFC5766](https://tools.ietf.org/html/rfc5766): Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
* [RFC5928](https://tools.ietf.org/html/rfc5928): Traversal Using Relays around NAT (TURN) Resolution Mechanism

Even moar:

* [RFC7350](https://tools.ietf.org/html/rfc7350): Datagram Transport Layer Security (DTLS) as Transport for Session Traversal Utilities for NAT (STUN)

# Observed in the wild

## Chrome's TURN

* C: Allocate Request [Requested-Transport]
* S: Allocate Error [Error-Code, Nonce, Realm, Software, Fingerprint]
* C: Allocate Request [Request-Transport, Username, Realm, Nonce, Message-Integrity]
* S: Allocate Success [XOR-Relayed-Address, XOR-Mapped-Address, Lifetime, Software, Message-Integrity, Fingerprint]
* C: Refresh Request [Lifetime, Username, Realm, Nonce, Message-Integrity]
* S: Refresh Success [Lifetime, Software, Message-Integrity, Fingerprint]

## Firefox's TURN

* C: Allocate Request [Requested-Transport]
* S: Allocate Error [Error-Code, Nonce, Realm, Software, Fingerprint]
* C: Allocate Request [Request-Transport, Username, Realm, Nonce, Message-Integrity]
* S: Allocate Success [XOR-Relayed-Address, XOR-Mapped-Address, Lifetime, Software, Message-Integrity, Fingerprint]
* C: Refresh Request [Lifetime, Username, Realm, Nonce, Message-Integrity]
* S: Refresh Success [Lifetime, Software, Message-Integrity, Fingerprint]
