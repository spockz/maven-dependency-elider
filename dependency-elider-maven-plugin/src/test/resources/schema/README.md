<!-- WHY: Records the source and digest of the CVE schema used by synthetic fixture tests. -->
# Pinned CVE Record Format schema

`cve-record-format-5.2.0-bundled.json` is the bundled CVE Record Format 5.2.0
schema from the official [CVEProject/cve-schema repository](https://github.com/CVEProject/cve-schema/blob/5.2.0/schema/docs/CVE_Record_Format_bundled.json).
Its SHA-256 is
`44c703322b1fcc532bc1c93f3993a0ba042c1a2831aae8cf39c4fbb707d03c8f`.
The publication regression checks this digest before validating its clearly
synthetic, test-only CVE record.
