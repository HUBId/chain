# STWO mini golden vectors

Dieses Verzeichnis friert die deterministische Mini-Fixture ein, die im Test
`tests/golden_vector_export.rs` erzeugt und verifiziert wird. Die Artefakte
werden ausschließlich über die kanonischen Serialisierer geschrieben; Details
zu Encoding und Prüfschritten finden sich in
[`docs/STWO_INTEROP.md`](../../docs/STWO_INTEROP.md), der
[Public-Inputs-Encoding-Spezifikation](../../docs/PUBLIC_INPUTS_ENCODING.md)
und dem [Proof-Size-Gate](../../docs/PROOF_SIZE_GATE.md).

Alle Dateien sind Teil des Golden-Baselinesatzes: `params.bin`,
`public_inputs.bin`, `public_digest.hex`, `proof.bin`, `proof_report.json`,
`roots.json`, `challenges.json` sowie `indices.json`. Um das Repository ohne
Binärfilter betreiben zu können, enthalten die `*.bin`-Dateien die kanonischen
Bytes als durchgehenden Hex-String (mit abschließendem Newline). Beim Import
muss der Hex-String ohne Whitespace in Bytes dekodiert werden. Bei identischen
Inputs müssen wiederholte Läufe byteidentische Artefakte erzeugen; Abweichungen
deuten auf eine Verletzung der dokumentierten Invarianten hin.【F:tests/golden_vector_export.rs†L18-L176】【F:tests/golden_vector_export.rs†L178-L241】
