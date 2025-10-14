# SPDX-FileCopyrightText: 2017 Scott Shawcroft, written for Adafruit Industries
# SPDX-FileCopyrightText: Copyright (c) 2025 Shamba Chowdhury
#
# SPDX-License-Identifier: Unlicense

from circuitpython_miniethers import Signature, Wallet

# The private key is used for both signing methods
# IMPORTANT: In a real app, never hardcode private keys.
# Use environment variables or a secure wallet connection.
privateKey = "0x022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc"

# Create a wallet instance from the private key
wallet = Wallet(privateKey)


def generateFlatSignature():
    """
    Signs a simple string message (ERC-191).
    """
    print("--- Signing a Flat String (ERC-191) ---")

    # The message to sign
    message = "hello"

    print(f'Signing message: "{message}"')
    print(f"Signer Address: {wallet.address}")
    print("---")

    flatSignature = wallet.signMessage(message)

    print("Full Flat Signature:", flatSignature)

    # For comparison, let's split the signature into its components
    signature = getattr(Signature, "from")(flatSignature)
    print("Signature Components:")
    print("  r:", signature.r)
    print("  s:", signature.s)
    print("  v:", signature.v)
    print("-----------------------------------------\n")


def signTypedDataMail():
    """
    Signs structured typed data (EIP-712).
    This provides more readable and secure signing prompts in wallets like MetaMask.
    """
    print("--- Signing Typed Data (EIP-712) ---")

    # 1. The Domain Separator: Defines the context of the signature.
    # This prevents a signature from being valid in a different application.
    domain = {
        # The user-friendly name of the signing domain
        "name": "Ether Mail",
        # The current version of the signing domain
        "version": "1",
        # The chain ID of the intended network (1 for Ethereum Mainnet)
        "chainId": 1,
        # The address of the contract that will verify the signature
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    }

    # 2. The Types: Defines the structure of the data being signed.
    # You define your primary type ("Mail") and any custom nested types ("Person").
    types = {
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Mail": [
            {"name": "from", "type": "Person"},  # Nested custom type
            {"name": "to", "type": "Person"},  # Nested custom type
            {"name": "contents", "type": "string"},
        ],
    }

    # 3. The Value: The actual data object to be signed.
    # This object must match the structure defined in `types`.
    value = {
        "from": {
            "name": "Cow",
            "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
        },
        "to": {
            "name": "Bob",
            "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
        },
        "contents": "Hello, Bob! This is a typed message.",
    }

    print("Signing EIP-712 data for address:", wallet.address)
    print("Domain:", domain)
    print("Value:", value)
    print("---")

    # The `_signTypedData` method handles hashing the structured data according to the EIP-712 spec.
    signature = wallet._signTypedData(domain, types, value)

    print("EIP-712 Signature:", signature)
    print("------------------------------------\n")


# Run both signing functions
def main():
    print("CircuitPython MiniEthers - Ethers.js Compatibility Test\n")
    print(f"Wallet Address: {wallet.address}")
    print(f"Private Key: {wallet.privateKey}")
    print(f"Public Key: {wallet.publicKey}\n")

    generateFlatSignature()
    signTypedDataMail()

    print("\n✅ All tests completed successfully!")


if __name__ == "__main__":
    main()
