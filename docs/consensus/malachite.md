# Malachite BFT Distributed Streams

The Malachite BFT blueprint requires validators to observe the same proposal,
vote, and commit flows even when they participate from different hosts. The new
`DistributedOrchestrator` wraps Tokio broadcast channels and exposes typed
subscriptions per stream so every node can publish to and consume from the
shared queues without out-of-band coordination.【F:rpp/consensus/src/malachite/distributed.rs†L1-L189】

Each node calls `DistributedOrchestrator::register_node` to obtain dedicated
`Proposal`, `Vote`, and `Commit` subscriptions. The helper `VoteMessage` enum
normalises pre-votes and pre-commits so downstream components can inspect the
block hash, round, or validator without juggling separate queues.【F:rpp/consensus/src/malachite/distributed.rs†L59-L156】

## Topic routing

Malachite commits must still reach the witness infrastructure so the STARK
pipeline can verify and archive proofs. The `TopicRouter` therefore assigns the
canonical consensus topic as the primary destination and automatically fans
commits out to the witness proof and metadata topics when witness routing is
enabled.【F:rpp/consensus/src/network/topics.rs†L1-L62】 This replaces the manual
callers that previously had to keep the witness topics in sync.

## Validation

The integration test `distributed_streams_propagate_across_nodes` exercises the
fan-out logic with two nodes, verifying that proposals, votes, and commits reach
all subscribers. It also checks that the topic router adds the witness topics to
the commit fan-out so the blueprint’s multi-node requirement can be considered
covered.【F:tests/consensus/malachite_distributed.rs†L1-L188】
