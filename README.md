# KslKatzBOF

A Beacon Object File (BOF) in-line LSASS credential extraction from C2 using the KslD.sys BYOVD technique.

## Attribution

This BOF is based on **KslKatz** (**Maximilian Barz**), which itself builds upon two foundational projects:

- **KslDump** – BYOVD physical memory access via KslD.sys (Microsoft Defender's kernel driver)
- **GhostKatz** – BOF-based LSASS extraction through physical memory 

## What It Does

Extracts credentials from PPL-protected LSASS without injecting into the process, using only Microsoft-signed components already present on disk:

- **MSV1_0** — NT hashes per logon session
- **WDigest** — Cleartext passwords (when caching is enabled)

## Building

```
make
```

Produces `bin/kslkatzbof.x64.o`.

## Usage

Load the BOF using your preferred BOF loader.

## Disclaimer

For authorized security testing only. Misuse of this tool against systems without explicit permission is illegal.
