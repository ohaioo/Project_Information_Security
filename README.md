## Setup

```bash
pip install -r requirements.txt
```

## Usage

Run the tool:

```bash
python integrity_tool.py
```

An interactive menu will appear:

```
========================================
  File Integrity & Digital Signature Tool
========================================
  1. Hash a file
  2. Generate manifest for a directory
  3. Check integrity against manifest
  4. Generate RSA key pair
  5. Sign a manifest
  6. Verify a signature
  0. Exit
========================================
  Select an option:
```

### Option 1 – Hash a file

Computes the SHA-256 hash of any file (text, PDF, image, etc.).

```
  Enter file path: report.pdf

  SHA-256: a3f2c8d...   File:    report.pdf
```

### Option 2 – Generate manifest

Scans a directory and produces a `metadata.json` listing every file and its SHA-256 hash.

```
  Enter directory path: ./documents

  Manifest created: ./documents/metadata.json
  Files hashed: 5
```

### Option 3 – Check integrity

Compares the current files against a previously generated `metadata.json` to detect tampering.

```
  Enter directory path (containing metadata.json): ./documents

  [OK]       budget.xlsx
  [MODIFIED] notes.txt
  [MISSING]  secret.docx

  Summary: 1 OK, 1 MODIFIED, 1 MISSING, 0 NEW
  Result: INTEGRITY CHECK FAILED – tampering detected.
```

### Option 4 – Generate RSA key pair

Creates a 2048-bit RSA key pair (`private_key.pem` and `public_key.pem`).

```
  Enter output directory for keys (default: current dir):

  Private key saved: ./private_key.pem
  Public  key saved: ./public_key.pem
```

### Option 5 – Sign a manifest

Signs the `metadata.json` using the sender's private key, producing `manifest.sig`.

```
  Enter path to private key (.pem): ./private_key.pem
  Enter directory containing metadata.json: ./documents

  Signature saved: ./documents/manifest.sig
```

### Option 6 – Verify a signature

Verifies the signature with the sender's public key, then checks file integrity.

```
  Enter path to sender's public key (.pem): ./public_key.pem
  Enter path to signature file (.sig): ./documents/manifest.sig
  Enter directory containing metadata.json and files: ./documents

  [PASS] Signature is valid – the manifest is authentic.

  Running file integrity check against the manifest ...

  [OK]       budget.xlsx
  [OK]       notes.txt

  Summary: 2 OK, 0 MODIFIED, 0 MISSING, 0 NEW
  Result: ALL FILES OK.
```

## Typical Workflow

**Sender** side:

1. Option **2** – Generate the manifest for a directory of files
2. Option **4** – Generate an RSA key pair
3. Option **5** – Sign the manifest with the private key
4. Send the directory (files + `metadata.json` + `manifest.sig`) and the `public_key.pem` to the receiver

**Receiver** side:

5. Option **6** – Verify using the sender's public key, signature file, and directory

## Libraries

| Library | Purpose |
|---------|---------|
| `hashlib` (stdlib) | SHA-256 file hashing |
| `cryptography` | RSA key generation, signing, and verification |
