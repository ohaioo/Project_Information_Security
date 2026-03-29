import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------------------------
# Task 1 – SHA-256 hashing
# ---------------------------------------------------------------------------

def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------------------------------------------------------------------------
# Task 2 – Manifest generation
# ---------------------------------------------------------------------------

SKIP_FILES = {"metadata.json", "manifest.sig", "private_key.pem", "public_key.pem"}


def generate_manifest(directory):
    entries = []
    for root, _dirs, files in os.walk(directory):
        _dirs[:] = [d for d in _dirs if not d.startswith(".")]
        for fname in sorted(files):
            if fname.startswith(".") or fname in SKIP_FILES:
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, directory)
            file_hash = hash_file(full_path)
            entries.append({"filename": rel_path, "sha256": file_hash})

    entries.sort(key=lambda e: e["filename"])

    manifest_path = os.path.join(directory, "metadata.json")
    with open(manifest_path, "w") as f:
        json.dump(entries, f, indent=2)

    return manifest_path, entries


# ---------------------------------------------------------------------------
# Task 3 – Integrity check
# ---------------------------------------------------------------------------

def check_integrity(directory):
    manifest_path = os.path.join(directory, "metadata.json")
    if not os.path.isfile(manifest_path):
        print(f"  [ERROR] metadata.json not found in {directory}")
        return False

    with open(manifest_path, "r") as f:
        entries = json.load(f)

    ok = modified = missing = 0
    manifest_names = set()

    for entry in entries:
        rel = entry["filename"]
        manifest_names.add(rel)
        full_path = os.path.join(directory, rel)

        if not os.path.isfile(full_path):
            print(f"  [MISSING]  {rel}")
            missing += 1
            continue

        current_hash = hash_file(full_path)
        if current_hash == entry["sha256"]:
            print(f"  [OK]       {rel}")
            ok += 1
        else:
            print(f"  [MODIFIED] {rel}")
            modified += 1

    new_count = 0
    for root, _dirs, files in os.walk(directory):
        _dirs[:] = [d for d in _dirs if not d.startswith(".")]
        for fname in sorted(files):
            if fname.startswith(".") or fname in SKIP_FILES:
                continue
            rel = os.path.relpath(os.path.join(root, fname), directory)
            if rel not in manifest_names:
                print(f"  [NEW]      {rel}")
                new_count += 1

    print(f"\n  Summary: {ok} OK, {modified} MODIFIED, {missing} MISSING, {new_count} NEW")
    tampered = (modified + missing + new_count) > 0
    if tampered:
        print("  Result: INTEGRITY CHECK FAILED – tampering detected.")
    else:
        print("  Result: ALL FILES OK.")
    return not tampered


# ---------------------------------------------------------------------------
# Task 4 – RSA key-pair generation
# ---------------------------------------------------------------------------

def generate_keys(output_dir="."):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    priv_path = os.path.join(output_dir, "private_key.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    pub_path = os.path.join(output_dir, "public_key.pem")
    with open(pub_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    return priv_path, pub_path


# ---------------------------------------------------------------------------
# Task 5 – Sign the manifest
# ---------------------------------------------------------------------------

def sign_manifest(private_key_path, directory):
    manifest_path = os.path.join(directory, "metadata.json")
    if not os.path.isfile(manifest_path):
        print(f"  [ERROR] metadata.json not found in {directory}")
        return None

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    manifest_hash = hashlib.sha256(open(manifest_path, "rb").read()).digest()

    signature = private_key.sign(
        manifest_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )

    sig_path = os.path.join(directory, "manifest.sig")
    with open(sig_path, "wb") as f:
        f.write(signature)

    return sig_path


# ---------------------------------------------------------------------------
# Task 6 – Verify signature + integrity
# ---------------------------------------------------------------------------

def verify_signature(public_key_path, signature_path, directory):
    manifest_path = os.path.join(directory, "metadata.json")
    if not os.path.isfile(manifest_path):
        print(f"  [ERROR] metadata.json not found in {directory}")
        return False

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    manifest_hash = hashlib.sha256(open(manifest_path, "rb").read()).digest()

    with open(signature_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            manifest_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
    except Exception:
        print("  [FAIL] Signature verification FAILED. The manifest may have been tampered with.")
        return False

    print("  [PASS] Signature is valid – the manifest is authentic.")
    print("\n  Running file integrity check against the manifest ...\n")
    return check_integrity(directory)


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

MENU = """
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
========================================"""


def prompt(message):
    return input(f"  {message}").strip()


def menu_hash_file():
    path = prompt("Enter file path: ")
    if not os.path.isfile(path):
        print(f"  [ERROR] File not found: {path}")
        return
    digest = hash_file(path)
    print(f"\n  SHA-256: {digest}")
    print(f"  File:    {path}")


def menu_generate_manifest():
    directory = prompt("Enter directory path: ")
    if not os.path.isdir(directory):
        print(f"  [ERROR] Directory not found: {directory}")
        return
    manifest_path, entries = generate_manifest(directory)
    print(f"\n  Manifest created: {manifest_path}")
    print(f"  Files hashed: {len(entries)}")


def menu_check_integrity():
    directory = prompt("Enter directory path (containing metadata.json): ")
    if not os.path.isdir(directory):
        print(f"  [ERROR] Directory not found: {directory}")
        return
    print()
    check_integrity(directory)


def menu_generate_keys():
    output_dir = prompt("Enter output directory for keys (default: current dir): ") or "."
    if not os.path.isdir(output_dir):
        print(f"  [ERROR] Directory not found: {output_dir}")
        return
    priv_path, pub_path = generate_keys(output_dir)
    print(f"\n  Private key saved: {priv_path}")
    print(f"  Public  key saved: {pub_path}")


def menu_sign_manifest():
    private_key_path = prompt("Enter path to private key (.pem): ")
    if not os.path.isfile(private_key_path):
        print(f"  [ERROR] File not found: {private_key_path}")
        return
    directory = prompt("Enter directory containing metadata.json: ")
    if not os.path.isdir(directory):
        print(f"  [ERROR] Directory not found: {directory}")
        return
    sig_path = sign_manifest(private_key_path, directory)
    if sig_path:
        print(f"\n  Signature saved: {sig_path}")


def menu_verify_signature():
    public_key_path = prompt("Enter path to sender's public key (.pem): ")
    if not os.path.isfile(public_key_path):
        print(f"  [ERROR] File not found: {public_key_path}")
        return
    signature_path = prompt("Enter path to signature file (.sig): ")
    if not os.path.isfile(signature_path):
        print(f"  [ERROR] File not found: {signature_path}")
        return
    directory = prompt("Enter directory containing metadata.json and files: ")
    if not os.path.isdir(directory):
        print(f"  [ERROR] Directory not found: {directory}")
        return
    print()
    verify_signature(public_key_path, signature_path, directory)


ACTIONS = {
    "1": menu_hash_file,
    "2": menu_generate_manifest,
    "3": menu_check_integrity,
    "4": menu_generate_keys,
    "5": menu_sign_manifest,
    "6": menu_verify_signature,
}


def main():
    while True:
        print(MENU)
        choice = prompt("Select an option: ")

        if choice == "0":
            print("\n  Goodbye.\n")
            break

        action = ACTIONS.get(choice)
        if action is None:
            print("  [ERROR] Invalid option. Please enter 0-6.")
            continue

        print()
        try:
            action()
        except KeyboardInterrupt:
            print("\n  Operation cancelled.")
        except Exception as e:
            print(f"  [ERROR] {e}")
        print()


if __name__ == "__main__":
    main()
