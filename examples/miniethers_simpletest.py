# SPDX-FileCopyrightText: 2017 Scott Shawcroft, written for Adafruit Industries
# SPDX-FileCopyrightText: Copyright (c) 2025 Shamba Chowdhury
#
# SPDX-License-Identifier: Unlicense

from circuitpython_miniethers import Wallet


def example_basic_wallet():
    """Example 1: Create a wallet and get its address"""
    print("=== Example 1: Basic Wallet Creation ===\n")

    # Create a new wallet with randomly generated private key
    wallet = Wallet()

    print(f"Address: {wallet.get_address()}")
    print(f"Private Key: 0x{wallet._int_to_hex(wallet.get_private_key())}")

    pub_x, pub_y = wallet.get_public_key()
    print(f"Public Key X: 0x{wallet._int_to_hex(pub_x)}")
    print(f"Public Key Y: 0x{wallet._int_to_hex(pub_y)}")
    print()


def example_from_private_key():
    """Example 2: Create a wallet from existing private key"""
    print("=== Example 2: Wallet from Private Key ===\n")

    # Example private key (this is just for demonstration)
    private_key = 0x022B99092266A16A949E6A450F0E88A8288D39D5F1D75C00575A35A0BA270DBC

    wallet = Wallet(private_key)

    print(f"Address: {wallet.get_address()}")
    print(f"Private Key: 0x{wallet._int_to_hex(private_key)}")
    print()


def example_sign_personal_message():
    """Example 3: Sign a personal message (ERC-191)"""
    print("=== Example 3: Sign Personal Message ===\n")

    wallet = Wallet()
    message = "Hello, Ethereum!"

    print(f"Wallet Address: {wallet.get_address()}")
    print(f"Message: {message}")

    # Sign the message
    signature = wallet.sign_message(message)

    print(f"\nSignature:")
    print(f"  r: {signature['r']}")
    print(f"  s: {signature['s']}")
    print(f"  v: {signature['v']}")
    print()


def example_sign_typed_data():
    """Example 4: Sign EIP-712 typed data"""
    print("=== Example 4: Sign Typed Data (EIP-712) ===\n")

    wallet = Wallet()

    # Define the domain
    domain = {
        "name": "Example App",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x1234567890123456789012345678901234567890",
    }

    # Define custom types
    types = {
        "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
        "Message": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "content", "type": "string"},
        ],
    }

    # Create the message
    message = {
        "from": {"name": "Alice", "wallet": "0xAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAb"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "content": "Hello Bob!",
    }

    primary_type = "Message"

    print(f"Wallet Address: {wallet.get_address()}")
    print(f"Domain: {domain}")
    print(f"Message: {message}")

    # Sign the typed data
    signature = wallet.sign_typed_data(domain, types, primary_type, message)

    print(f"\nEIP-712 Signature:")
    print(f"  r: {signature['r']}")
    print(f"  s: {signature['s']}")
    print(f"  v: {signature['v']}")
    print()


def example_verify_signature():
    """Example 5: Verify a signature"""
    print("=== Example 5: Verify Signature ===\n")

    wallet = Wallet()
    message = "Verify me!"

    print(f"Wallet Address: {wallet.get_address()}")
    print(f"Message: {message}")

    # Sign the message
    signature = wallet.sign_message(message)
    print(f"\nSignature: {signature}")

    # Create the message hash
    message_hash = wallet._create_ethereum_message_hash(message)

    # Extract r and s from signature
    r = int(signature["r"], 16)
    s = int(signature["s"], 16)

    # Verify the signature
    is_valid = wallet.verify_signature(message_hash, r, s)

    print(f"Signature valid: {is_valid}")
    print()


def example_multiple_signers():
    """Example 6: Multiple wallets signing same data"""
    print("=== Example 6: Multiple Signers ===\n")

    message = "Multi-sig example"

    print(f"Message: {message}")
    print(f"\nCreating 3 wallets and signing...\n")

    signatures = []

    for i in range(3):
        wallet = Wallet()
        signature = wallet.sign_message(message)

        print(f"Wallet {i+1}: {wallet.get_address()}")
        print(f"Signature: v={signature['v']}, r={signature['r']}, s={signature['s']}\n")

        signatures.append((wallet, signature))

    # You could now use these signatures for multi-sig verification
    # (implementation would depend on your specific use case)
    print(f"Total signatures collected: {len(signatures)}")
    print()


def example_different_messages():
    """Example 7: Sign different message types"""
    print("=== Example 7: Different Message Types ===\n")

    wallet = Wallet()

    messages = [
        "Short message",
        "A much longer message that contains more information and details for testing",
        "123456",
        "Special chars: @#$%^&*()",
    ]

    print(f"Wallet Address: {wallet.get_address()}\n")

    for msg in messages:
        signature = wallet.sign_message(msg)
        print(f"Message: {msg}")
        print(f"  v: {signature['v']}")
        print(f"  r: {signature['r'][:20]}...")
        print(f"  s: {signature['s'][:20]}...\n")


if __name__ == "__main__":
    """Run all examples"""
    try:
        example_basic_wallet()
        example_from_private_key()
        example_sign_personal_message()
        example_sign_typed_data()
        example_verify_signature()
        example_multiple_signers()
        example_different_messages()

        print("=== All Examples Completed Successfully ===")

    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
