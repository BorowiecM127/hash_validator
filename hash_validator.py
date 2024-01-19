"""Script validating file SHA-256 hash with hash string"""
import hashlib
import argparse


def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Calculate and compare SHA-256 hash for a file."
    )

    parser.add_argument("file_path", help="Path to the file")
    parser.add_argument("hash_string", help="SHA-256 hash string")

    args = parser.parse_args()

    calculated_hash = calculate_sha256(args.file_path)

    print(f"calculated hash: {calculated_hash.lower()}")
    print(f"    hash_string: {args.hash_string.lower()}")

    if calculated_hash.lower() == args.hash_string.lower():
        print("Hashes are equal!")
    else:
        print("Hashes are not equal!")


if __name__ == "__main__":
    main()
