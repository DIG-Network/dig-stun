# dig-stun

The canonical, ecosystem-wide implementation of how a DIG node learns — and **believes** — its own
public address.

`SPEC.md` is normative and is the contract an independent reimplementation is built against.

## What this crate owns

- The **RFC 5389 Binding codec**, both directions.
- The **client** transaction: one UDP exchange, CSPRNG transaction id, response-source validation.
- The **single address-scope table**. `Scope::{NeverDialable, PrivateScope, GlobalUnicast}`, with
  `is_usable_reflexive_addr` (the dial guard, which keeps LAN/CGNAT/ULA) and `is_globally_routable`
  (the on-chain advertisement gate) as its two derived predicates. **No other crate carries a range
  table for either question.**
- **Peer observation** — `observe`, which answers only over an inbound, non-relayed session, plus its
  transport-keyed limiter. **A DIG node never opens a UDP STUN listener.**
- **Agreement** — `establish`: per address family, a unanimous IP across all readings, at least two
  independent source classes (three when every class is a peer), and global unicast. One dissenter
  blocks; it fails closed.

## Why agreement, and not a single answer

A STUN responder reports *your* address, so a hostile or misconfigured one can make you believe an
address you do not own. Measured on 2026-09-05: `relay.dig.net` answered IPv4 callers with **its own
load balancer's address**, 10 requests out of 10, each with a correct magic cookie, a matching
transaction id, and a real globally-routable value. Nothing errored and nothing looked stale.

A DIG node writes its address on chain and bonds collateral against it, so a plausible wrong answer is
worse than no answer at all: a null address is visible, and a wrong one is not.

## Status

Pre-release. The API is not stable until `0.1.1` is published.
