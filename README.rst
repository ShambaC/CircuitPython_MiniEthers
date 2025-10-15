Introduction
============


.. image:: https://readthedocs.org/projects/circuitpython-miniethers/badge/?version=latest
    :target: https://circuitpython-miniethers.readthedocs.io/
    :alt: Documentation Status



.. image:: https://img.shields.io/discord/327254708534116352.svg
    :target: https://adafru.it/discord
    :alt: Discord


.. image:: https://github.com/ShambaC/CircuitPython_MiniEthers/workflows/Build%20CI/badge.svg
    :target: https://github.com/ShambaC/CircuitPython_MiniEthers/actions
    :alt: Build Status


.. image:: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json
    :target: https://github.com/astral-sh/ruff
    :alt: Code Style: Ruff

Circuitpython module for ethereum wallet creation and signing


Dependencies
=============
This driver depends on:

* `Adafruit CircuitPython <https://github.com/adafruit/circuitpython>`_

Please ensure all dependencies are available on the CircuitPython filesystem.
This is easily achieved by downloading
`the Adafruit library and driver bundle <https://circuitpython.org/libraries>`_
or individual libraries can be installed using
`circup <https://github.com/adafruit/circup>`_.

Installing from PyPI
=====================

On supported GNU/Linux systems like the Raspberry Pi, you can install the driver locally `from
PyPI <https://pypi.org/project/circuitpython-miniethers/>`_.
To install for current user:

.. code-block:: shell

    pip3 install circuitpython-miniethers

To install system-wide (this may be required in some cases):

.. code-block:: shell

    sudo pip3 install circuitpython-miniethers

To install in a virtual environment in your current project:

.. code-block:: shell

    mkdir project-name && cd project-name
    python3 -m venv .venv
    source .env/bin/activate
    pip3 install circuitpython-miniethers

Installing to a Connected CircuitPython Device with Circup
==========================================================

Make sure that you have ``circup`` installed in your Python environment.
Install it with the following command if necessary:

.. code-block:: shell

    pip3 install circup

With ``circup`` installed and your CircuitPython device connected use the
following command to install:

.. code-block:: shell

    circup install miniethers

Or the following command to update an existing version:

.. code-block:: shell

    circup update

Usage Example
=============

Simple example showcasing wallet creation and message signing.

.. code-block:: python

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


Documentation
=============
API documentation for this library can be found on `Read the Docs <https://circuitpython-miniethers.readthedocs.io/>`_.

For information on building library documentation, please check out
`this guide <https://learn.adafruit.com/creating-and-sharing-a-circuitpython-library/sharing-our-docs-on-readthedocs#sphinx-5-1>`_.

Contributing
============

Contributions are welcome! Please read our `Code of Conduct
<https://github.com/ShambaC/CircuitPython_MiniEthers/blob/HEAD/CODE_OF_CONDUCT.md>`_
before contributing to help this project stay welcoming.


PS
===

I participated in EthGlobal New Delhi this year where me and my team created a hardware wallet for our project. For that purpose we chose a Raspberry Pi Pico. And that is when we realised that the hardware is pretty constrained which doesnt allow existing libraries to work. So I wrote a package that worked on the Pico.

And after some time I decided that I should package this properly and share it as a library, so that people can use this if they want to. That's the story behind this package.
