"""Script validating file SHA-256 hash with hash string"""

from hashlib import sha256
import argparse
from _hashlib import HASH


def calculate_sha256(file_path: str) -> str:
    """Calculates the SHA-256 hash of a file."""
    sha256_hash: HASH = sha256()
    with open(file=file_path, mode="rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def main() -> None:
    """Main function"""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Calculate and compare SHA-256 hash for a file."
    )

    parser.add_argument("file_path", help="Path to the file")
    parser.add_argument("hash_string", help="SHA-256 hash string")

    args: argparse.Namespace = parser.parse_args()

    calculated_hash: str = calculate_sha256(file_path=args.file_path)

    print(f"calculated hash: {calculated_hash.lower()}")
    print(f"    hash_string: {args.hash_string.lower()}")

    if calculated_hash.lower() == args.hash_string.lower():
        print("Hashes are equal!")
    else:
        print("Hashes are not equal!")


if __name__ == "__main__":
    main()
