# Range proof serialization

Firewood range proofs are serialized using the V0 wire format described in
`firewood/src/proofs/ser.rs`. Each sequence in the payload (start proof nodes,
end proof nodes, and key/value pairs) is prefixed with an unsigned LEB128 count.

## Collection limits

The V0 decoder enforces an upper bound of 4,096 elements for every range proof
collection (start proof nodes, end proof nodes, and key/value pairs). This limit
prevents oversized payloads from exhausting memory while keeping enough headroom
for realistic snapshots. Integrations that produce proofs must ensure each of
those sequences stays at or below 4,096 entries.
