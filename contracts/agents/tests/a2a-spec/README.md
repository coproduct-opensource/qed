# A2A specification file used by the tests

`a2a.proto` is the Agent2Agent protocol's canonical data model, copied
unmodified from `specification/a2a.proto` of
<https://github.com/a2aproject/A2A> at commit
`d18aa92c911c1b49f0d584c1ca0e9d8718391014` (fetched 2026-11-12; the
specification's latest released version there is 1.0.0). SHA-256
`945df6e34001b2bfd0fd62d9484b63094dfad9d78705e41e2873441c419ae2d1`.
License: Apache-2.0, as that repository's `LICENSE` states.

`tests/a2a.rs` reads it for each message's field names and which fields are
`REQUIRED`, and checks every object the agent emits against that. The
project's JSON Schema (`a2a.json`) is generated from this file and, by its
own README, is a non-normative build artifact with no `required` lists, so
the proto is the source used here.
