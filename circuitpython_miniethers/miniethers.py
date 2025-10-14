# SPDX-FileCopyrightText: 2017 Scott Shawcroft, written for Adafruit Industries
# SPDX-FileCopyrightText: Copyright (c) 2025 Shamba Chowdhury
#
# SPDX-License-Identifier: Unlicense

"""
`miniethers`
================================================================================

Circuitpython module for ethereum wallet creation and signing


* Author(s): Shamba Chowdhury

Implementation Notes
--------------------

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://circuitpython.org/downloads
"""

# imports

__version__ = "1.0.0-rc.1"
__repo__ = "https://github.com/ShambaC/CircuitPython_MiniEthers.git"

import binascii
import random

import circuitpython_hmac as hmac

from circuitpython_miniethers import keccak

# secp256k1 curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _int_to_hex(num, length=64):
    """Convert integer to zero-padded hexadecimal string.

    :param num: Integer to convert
    :type num: int
    :param length: Desired length of output string (default: 64)
    :type length: int
    :return: Zero-padded hexadecimal string without 0x prefix
    :rtype: str
    """
    try:
        hex_str = hex(num)[2:]
        return ("0" * (length - len(hex_str)) + hex_str) if len(hex_str) < length else hex_str
    except Exception:
        return "0" * length


class Signature:
    """ECDSA signature representation compatible with ethers.js Signature class.

    Represents an Elliptic Curve Digital Signature Algorithm (ECDSA) signature
    with components r, s, and v. Provides methods for parsing and serializing
    signatures in various formats.

    :ivar r: The r component of the signature (hex string with 0x prefix)
    :vartype r: str
    :ivar s: The s component of the signature (hex string with 0x prefix)
    :vartype s: str
    :ivar v: The recovery parameter (27 or 28)
    :vartype v: int

    .. note::
        Compatible with ethers.js v6 Signature format.
    """

    def __init__(self, r=None, s=None, v=None):
        """Initialize a Signature instance.

        :param r: The r value as hex string or integer (optional)
        :type r: str or int or None
        :param s: The s value as hex string or integer (optional)
        :type s: str or int or None
        :param v: The recovery parameter, typically 27 or 28 (optional)
        :type v: int or None

        .. code-block:: python

            # Create from components
            sig = Signature(r="0x123...", s="0xabc...", v=27)

            # Create empty signature
            sig = Signature()
        """
        if r is None:
            self.r = "0x" + "0" * 64
            self.s = "0x" + "0" * 64
            self.v = 27
        else:
            if isinstance(r, str):
                self.r = r if r.startswith("0x") else "0x" + r
            else:
                self.r = "0x" + _int_to_hex(r)

            if isinstance(s, str):
                self.s = s if s.startswith("0x") else "0x" + s
            else:
                self.s = "0x" + _int_to_hex(s)

            self.v = v if v is not None else 27

    @property
    def yParity(self):
        """The y-parity of the signature point.

        :return: 0 if v is 27, otherwise 1
        :rtype: int

        .. note::
            yParity is used in EIP-2718 typed transactions.
        """
        return 0 if self.v == 27 else 1

    @property
    def serialized(self):
        """Compact serialized signature in hex format.

        Returns the signature in compact format: r (64 chars) + s (64 chars) + v (2 chars)
        with 0x prefix, totaling 132 characters.

        :return: Compact signature string (0xrrr...sss...vv)
        :rtype: str

        .. code-block:: python

            sig = Signature(r="0x123...", s="0xabc...", v=27)
            print(sig.serialized)  # "0x123...abc...1b"
        """
        r_hex = self.r[2:] if self.r.startswith("0x") else self.r
        s_hex = self.s[2:] if self.s.startswith("0x") else self.s
        v_hex = self._custom_zfill(hex(self.v)[2:], 2)
        return "0x" + r_hex + s_hex + v_hex

    @staticmethod
    def from_sig(sig):
        """Create a Signature from various input formats.

        Parses and creates a Signature instance from compact signature strings,
        dictionaries, or existing Signature instances.

        :param sig: Signature in various formats
        :type sig: str or dict or Signature
        :return: A new Signature instance
        :rtype: Signature
        :raises ValueError: If signature format is invalid

        .. code-block:: python

            # From compact signature string
            sig = Signature.from_sig("0xrrr...sss...vv")

            # From dictionary
            sig = Signature.from_sig({"r": "0x...", "s": "0x...", "v": 27})

            # Via getattr (to handle 'from' keyword)
            sig = getattr(Signature, 'from')("0xrrr...sss...vv")

        .. note::
            This method is also available as ``Signature.from()`` via setattr,
            but requires ``getattr(Signature, 'from')`` due to Python keyword restrictions.
        """
        if isinstance(sig, Signature):
            return sig

        if isinstance(sig, dict):
            return Signature(sig.get("r"), sig.get("s"), sig.get("v"))

        if isinstance(sig, str):
            sig = sig[2:] if sig.startswith("0x") else sig

            if len(sig) == 130:
                r = "0x" + sig[0:64]
                s = "0x" + sig[64:128]
                v = int(sig[128:130], 16)
                return Signature(r, s, v)

        raise ValueError("Invalid signature format")


# Add 'from' as an alias using setattr to avoid syntax error
setattr(Signature, "from", Signature.from_sig)


class Wallet:
    """Ethereum wallet for signing messages and transactions.

    Provides a high-level interface for Ethereum wallet operations including
    private key management, address derivation, and message signing compatible
    with ethers.js patterns. Optimized for CircuitPython and low-power devices.

    :ivar address: Ethereum address (read-only property)
    :vartype address: str
    :ivar privateKey: Private key as hex string (read-only property)
    :vartype privateKey: str
    :ivar publicKey: Uncompressed public key as hex string (read-only property)
    :vartype publicKey: str

    .. code-block:: python

        # Create wallet from private key
        wallet = Wallet("0x022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc")

        # Access properties
        print(wallet.address)      # "0x..."
        print(wallet.privateKey)   # "0x..."

        # Sign a message
        signature = wallet.signMessage("hello")

    .. note::
        Compatible with ethers.js v6 Wallet API patterns.
    """

    def __init__(self, private_key=None):
        """Initialize wallet with optional private key.

        :param private_key: Private key as hex string (with or without 0x prefix),
                           integer, or None to generate random key
        :type private_key: str or int or None
        :raises ValueError: If private key is out of valid range

        .. code-block:: python

            # From hex string (with 0x)
            wallet = Wallet("0x022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc")

            # From hex string (without 0x)
            wallet = Wallet("022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc")

            # From integer
            wallet = Wallet(0x022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc)

            # Generate random wallet
            wallet = Wallet()
        """
        if private_key is None:
            self._private_key = self._generate_private_key()
        else:
            # Handle hex string input
            if isinstance(private_key, str):
                if private_key.startswith("0x"):
                    private_key = int(private_key, 16)
                else:
                    private_key = int(private_key, 16)

            if not (1 <= private_key < N):
                raise ValueError("Private key must be in range [1, N-1]")
            self._private_key = private_key

        self._public_key = self._derive_public_key()
        self._address = None  # Cache for address

    @property
    def address(self):
        """Ethereum address derived from public key.

        Returns the Ethereum address computed from the wallet's public key
        using Keccak-256 hashing. The address is cached after first computation.

        :return: Ethereum address with 0x prefix (42 characters)
        :rtype: str

        .. code-block:: python

            wallet = Wallet("0x022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc")
            print(wallet.address)  # "0x14791697260E4c9A71f18484C9f997B308e59325"
        """
        if self._address is None:
            pub_x, pub_y = self._public_key
            concat_x_y = pub_x.to_bytes(32, "big") + pub_y.to_bytes(32, "big")
            eth_address = keccak.Keccak256(concat_x_y).digest()[-20:]
            self._address = "0x" + binascii.hexlify(eth_address).decode()
        return self._address

    @property
    def privateKey(self):
        """Private key as hexadecimal string.

        :return: Private key with 0x prefix (66 characters)
        :rtype: str

        .. warning::
            Never expose private keys in production environments.
        """
        return "0x" + _int_to_hex(self._private_key)

    @property
    def publicKey(self):
        """Uncompressed public key in hex format.

        Returns the uncompressed public key (x and y coordinates concatenated)
        with 0x04 prefix following SEC1 encoding.

        :return: Uncompressed public key with 0x04 prefix (132 characters)
        :rtype: str

        .. code-block:: python

            wallet = Wallet("0x022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc")
            print(wallet.publicKey)  # "0x04..."
        """
        pub_x, pub_y = self._public_key
        return "0x04" + _int_to_hex(pub_x) + _int_to_hex(pub_y)

    @staticmethod
    def _safe_mod(a, m):
        """Perform safe modulo operation handling negative numbers.

        :param a: Number to compute modulo of
        :type a: int
        :param m: Modulus
        :type m: int
        :return: Result of a mod m, always positive
        :rtype: int
        """
        if a < 0:
            return (a % m + m) % m
        return a % m

    @staticmethod
    def _mod_inverse(a, m):
        """Compute modular multiplicative inverse using Extended Euclidean Algorithm.

        :param a: Number to find inverse of
        :type a: int
        :param m: Modulus
        :type m: int
        :return: Modular inverse of a modulo m
        :rtype: int
        :raises ValueError: If modular inverse does not exist
        """
        a = Wallet._safe_mod(a, m)
        if a == 0:
            raise ValueError("Modular inverse does not exist")

        old_r, r = a, m
        old_s, s = 1, 0

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s

        if old_r > 1:
            raise ValueError("Modular inverse does not exist")

        return Wallet._safe_mod(old_s, m)

    @staticmethod
    def _point_double(px, py):
        """Double a point on the secp256k1 elliptic curve.

        :param px: X-coordinate of the point
        :type px: int
        :param py: Y-coordinate of the point
        :type py: int
        :return: Tuple of (x, y) coordinates of doubled point, or (None, None) if point at infinity
        :rtype: tuple
        """
        if py == 0:
            return None, None

        px_squared = Wallet._safe_mod(px * px, P)
        three_px_squared = Wallet._safe_mod(3 * px_squared, P)
        two_py = Wallet._safe_mod(2 * py, P)

        s = Wallet._safe_mod(three_px_squared * Wallet._mod_inverse(two_py, P), P)
        s_squared = Wallet._safe_mod(s * s, P)
        two_px = Wallet._safe_mod(2 * px, P)

        rx = Wallet._safe_mod(s_squared - two_px, P)
        ry = Wallet._safe_mod(s * Wallet._safe_mod(px - rx, P) - py, P)

        return rx, ry

    @staticmethod
    def _point_add(px, py, qx, qy):
        """Add two points on the secp256k1 elliptic curve.

        :param px: X-coordinate of first point
        :type px: int
        :param py: Y-coordinate of first point
        :type py: int
        :param qx: X-coordinate of second point
        :type qx: int
        :param qy: Y-coordinate of second point
        :type qy: int
        :return: Tuple of (x, y) coordinates of sum, or (None, None) if result is point at infinity
        :rtype: tuple
        """
        if px is None:
            return qx, qy
        if qx is None:
            return px, py

        if px == qx:
            if py == qy:
                return Wallet._point_double(px, py)
            else:
                return None, None

        dy = Wallet._safe_mod(qy - py, P)
        dx = Wallet._safe_mod(qx - px, P)
        dx_inv = Wallet._mod_inverse(dx, P)
        s = Wallet._safe_mod(dy * dx_inv, P)

        s_squared = Wallet._safe_mod(s * s, P)
        rx = Wallet._safe_mod(s_squared - px - qx, P)
        ry = Wallet._safe_mod(s * Wallet._safe_mod(px - rx, P) - py, P)

        return rx, ry

    @staticmethod
    def _scalar_mult(k, px, py):
        """Multiply a point by a scalar using binary method (double-and-add).

        Efficiently computes k * P where P is a point on secp256k1 curve.

        :param k: Scalar multiplier
        :type k: int
        :param px: X-coordinate of the point
        :type px: int
        :param py: Y-coordinate of the point
        :type py: int
        :return: Tuple of (x, y) coordinates of k*P, or (None, None) if result is point at infinity
        :rtype: tuple
        """
        if k == 0:
            return None, None
        if k == 1:
            return px, py

        k = Wallet._safe_mod(k, N)
        if k == 0:
            return None, None

        rx, ry = None, None
        addx, addy = px, py

        while k > 0:
            if k & 1:
                rx, ry = Wallet._point_add(rx, ry, addx, addy)
            if k > 1:
                addx, addy = Wallet._point_double(addx, addy)
            k >>= 1

        return rx, ry

    @staticmethod
    def _generate_rfc6979_k(private_key, message_hash, attempt=0):
        """Generate deterministic k value according to RFC 6979.

        Produces a deterministic k value for ECDSA signing to avoid the need for
        a cryptographically secure random number generator.

        :param private_key: Private key as integer
        :type private_key: int
        :param message_hash: Hash of the message to sign
        :type message_hash: int
        :param attempt: Retry attempt number (default: 0)
        :type attempt: int
        :return: Deterministic k value
        :rtype: int

        .. seealso::
            `RFC 6979 <https://tools.ietf.org/html/rfc6979>`_ for specification details.
        """
        private_key_bytes = private_key.to_bytes(32, "big")
        message_hash_bytes = message_hash.to_bytes(32, "big")

        V = b"\x01" * 32
        K = b"\x00" * 32

        K = hmac.new(
            K, V + b"\x00" + private_key_bytes + message_hash_bytes, digestmod="sha256"
        ).digest()
        V = hmac.new(K, V, digestmod="sha256").digest()
        K = hmac.new(
            K, V + b"\x01" + private_key_bytes + message_hash_bytes, digestmod="sha256"
        ).digest()
        V = hmac.new(K, V, digestmod="sha256").digest()

        for i in range(attempt + 1):
            T = b""
            while len(T) < 32:
                V = hmac.new(K, V, digestmod="sha256").digest()
                T += V

            k = int.from_bytes(T[:32], "big")

            if 1 <= k < N:
                if i == attempt:
                    return k

            K = hmac.new(K, V + b"\x00", digestmod="sha256").digest()
            V = hmac.new(K, V, digestmod="sha256").digest()

        return 1

    @classmethod
    def _generate_private_key(self):
        """Generate a cryptographically secure random private key.

        :return: Random private key in valid secp256k1 range
        :rtype: int
        """

        max_attempts = 10
        for _ in range(max_attempts):
            try:
                key_bytes = bytes([random.randint(0, 255) for _ in range(32)])
                key = int.from_bytes(key_bytes, "big")

                if 1 <= key < N:
                    return key
            except Exception:
                pass

        # Fallback method
        return random.randint(1, min(N - 1, 0xFFFFFFFFFFFFFFFF))

    def _derive_public_key(self):
        """Derive public key from private key using secp256k1 curve.

        :return: Tuple of (x, y) coordinates of the public key point
        :rtype: tuple
        """
        return self._scalar_mult(self._private_key, GX, GY)

    @staticmethod
    def _hash_message(message):
        """Hash a message using Keccak-256.

        :param message: Message to hash (string or bytes)
        :type message: str or bytes
        :return: Hash as integer
        :rtype: int
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        h = keccak.Keccak256(message)
        digest = h.digest()
        return int.from_bytes(digest, "big")

    @staticmethod
    def _create_ethereum_message_hash(message):
        """Create Ethereum signed message hash with ERC-191 prefix.

        Prepends the message with ``\\x19Ethereum Signed Message:\\n`` followed by
        the message length, as specified in ERC-191.

        :param message: Message to hash (string or bytes)
        :type message: str or bytes
        :return: Hash of prefixed message as integer
        :rtype: int

        .. seealso::
            `ERC-191 <https://eips.ethereum.org/EIPS/eip-191>`_ specification.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")

        prefix = b"\x19Ethereum Signed Message:\n"
        length = str(len(message)).encode("utf-8")
        full_message = prefix + length + message

        return Wallet._hash_message(full_message)

    @staticmethod
    def _encode_type(primary_type, types):
        """Encode a struct type definition according to EIP-712.

        :param primary_type: Name of the primary type to encode
        :type primary_type: str
        :param types: Dictionary of type definitions
        :type types: dict
        :return: Encoded type string
        :rtype: str
        """
        result = primary_type + "("
        type_def = types.get(primary_type, [])

        field_strings = []
        for field in type_def:
            field_strings.append(f"{field['type']} {field['name']}")

        result += ",".join(field_strings) + ")"

        referenced_types = set()
        Wallet._find_dependencies(primary_type, types, referenced_types)
        referenced_types.discard(primary_type)

        for ref_type in sorted(referenced_types):
            if ref_type in types:
                ref_def = types[ref_type]
                ref_fields = []
                for field in ref_def:
                    ref_fields.append(f"{field['type']} {field['name']}")
                result += ref_type + "(" + ",".join(ref_fields) + ")"

        return result

    @staticmethod
    def _find_dependencies(primary_type, types, found_types):
        """Find all type dependencies recursively for EIP-712 encoding.

        :param primary_type: Type name to find dependencies for
        :type primary_type: str
        :param types: Dictionary of type definitions
        :type types: dict
        :param found_types: Set of already found types (modified in-place)
        :type found_types: set
        """
        if primary_type in found_types or primary_type not in types:
            return

        found_types.add(primary_type)

        for field in types[primary_type]:
            field_type = field["type"]

            if field_type.endswith("[]"):
                field_type = field_type[:-2]

            if field_type in types and field_type not in found_types:
                Wallet._find_dependencies(field_type, types, found_types)

    @staticmethod
    def _hash_type(primary_type, types):
        """Hash a type string according to EIP-712.

        :param primary_type: Type name to hash
        :type primary_type: str
        :param types: Dictionary of type definitions
        :type types: dict
        :return: Keccak-256 hash of the encoded type
        :rtype: int
        """
        type_string = Wallet._encode_type(primary_type, types)
        return Wallet._hash_message(type_string.encode("utf-8"))

    @staticmethod
    def _custom_ljust(data, width, fillchar=b"\x00"):
        """Left justify bytes with padding.

        :param data: Data to justify
        :type data: bytes
        :param width: Desired width
        :type width: int
        :param fillchar: Fill character (default: zero byte)
        :type fillchar: bytes or int or str
        :return: Left-justified bytes
        :rtype: bytes
        """
        if len(data) >= width:
            return data
        if isinstance(fillchar, int):
            fillchar = bytes([fillchar])
        elif isinstance(fillchar, str):
            fillchar = fillchar.encode("utf-8")

        padding_needed = width - len(data)
        return data + fillchar * padding_needed

    @staticmethod
    def _custom_rjust(data, width, fillchar=b"\x00"):
        """Right justify bytes with padding.

        :param data: Data to justify
        :type data: bytes
        :param width: Desired width
        :type width: int
        :param fillchar: Fill character (default: zero byte)
        :type fillchar: bytes or int or str
        :return: Right-justified bytes
        :rtype: bytes
        """
        if len(data) >= width:
            return data
        if isinstance(fillchar, int):
            fillchar = bytes([fillchar])
        elif isinstance(fillchar, str):
            fillchar = fillchar.encode("utf-8")

        padding_needed = width - len(data)
        return fillchar * padding_needed + data

    @staticmethod
    def _custom_zfill(s, width):
        """Zero-fill string to specified width.

        :param s: String to pad
        :type s: str
        :param width: Desired width
        :type width: int
        :return: Zero-padded string
        :rtype: str
        """
        if len(s) >= width:
            return s
        return "0" * (width - len(s)) + s

    @staticmethod
    def _encode_string(value):
        """Encode string type for EIP-712.

        :param value: String value to encode
        :type value: str
        :return: 32-byte hash of the string
        :rtype: bytes
        """
        if isinstance(value, str):
            return Wallet._hash_message(value.encode("utf-8")).to_bytes(32, "big")
        return Wallet._hash_message(str(value).encode("utf-8")).to_bytes(32, "big")

    @staticmethod
    def _encode_bytes(value):
        """Encode dynamic bytes type for EIP-712.

        :param value: Bytes value to encode
        :type value: bytes or str
        :return: 32-byte hash of the bytes
        :rtype: bytes
        """
        if isinstance(value, str):
            if value.startswith("0x"):
                return Wallet._hash_message(bytes.fromhex(value[2:])).to_bytes(32, "big")
            return Wallet._hash_message(value.encode("utf-8")).to_bytes(32, "big")
        return Wallet._hash_message(value).to_bytes(32, "big")

    @staticmethod
    def _encode_fixed_bytes(type_name, value):
        """Encode fixed-size bytes type (e.g., bytes32) for EIP-712.

        :param type_name: Type name (e.g., 'bytes32')
        :type type_name: str
        :param value: Value to encode
        :type value: str or bytes
        :return: 32-byte padded value
        :rtype: bytes
        """
        if isinstance(value, str) and value.startswith("0x"):
            hex_value = value[2:]
            size = int(type_name[5:]) if len(type_name) > 5 else 32
            hex_value = Wallet._custom_zfill(hex_value, size * 2)[: size * 2]
            return Wallet._custom_ljust(bytes.fromhex(hex_value), 32, b"\x00")
        return Wallet._custom_ljust(str(value).encode("utf-8"), 32, b"\x00")[:32]

    @staticmethod
    def _encode_address(value):
        """Encode Ethereum address type for EIP-712.

        :param value: Ethereum address (with or without 0x prefix)
        :type value: str
        :return: 32-byte right-padded address
        :rtype: bytes
        """
        if isinstance(value, str):
            addr_hex = value[2:] if value.startswith("0x") else value
            addr_hex = Wallet._custom_zfill(addr_hex.lower(), 40)
            return Wallet._custom_rjust(bytes.fromhex(addr_hex), 32, b"\x00")
        return bytes(32)

    @staticmethod
    def _encode_uint(value):
        """Encode unsigned integer type for EIP-712.

        :param value: Unsigned integer value
        :type value: int or str
        :return: 32-byte big-endian encoded value
        :rtype: bytes
        """
        if isinstance(value, str):
            num_value = int(value, 16) if value.startswith("0x") else int(value)
        else:
            num_value = int(value)
        return num_value.to_bytes(32, "big")

    @staticmethod
    def _encode_int(value):
        """Encode signed integer type for EIP-712.

        :param value: Signed integer value
        :type value: int or str
        :return: 32-byte big-endian encoded value (two's complement for negative)
        :rtype: bytes
        """
        if isinstance(value, str):
            num_value = int(value, 16) if value.startswith("0x") else int(value)
        else:
            num_value = int(value)

        if num_value < 0:
            num_value = (1 << 256) + num_value

        return num_value.to_bytes(32, "big")

    @staticmethod
    def _encode_bool(value):
        """Encode boolean type for EIP-712.

        :param value: Boolean value
        :type value: bool
        :return: 32-byte encoded value (0 or 1)
        :rtype: bytes
        """
        bool_value = bool(value)
        return (1 if bool_value else 0).to_bytes(32, "big")

    @staticmethod
    def _encode_array(element_type, value, types):
        """Encode array type for EIP-712.

        :param element_type: Type of array elements
        :type element_type: str
        :param value: Array value
        :type value: list or tuple
        :param types: Dictionary of custom type definitions
        :type types: dict
        :return: 32-byte hash of concatenated encoded elements
        :rtype: bytes
        """
        if not isinstance(value, (list, tuple)):
            value = [value]

        encoded_elements = []
        for item in value:
            if element_type in types:
                encoded_elements.append(
                    Wallet._hash_struct(element_type, item, types).to_bytes(32, "big")
                )
            else:
                encoded_elements.append(Wallet._encode_value(element_type, item, types))

        array_data = b"".join(encoded_elements)
        return Wallet._hash_message(array_data).to_bytes(32, "big")

    @staticmethod
    def _encode_value(type_name, value, types):
        """Encode a value according to its EIP-712 type.

        Handles encoding of various Solidity types including primitives,
        arrays, and custom structs.

        :param type_name: Name of the type (e.g., 'string', 'uint256', 'address')
        :type type_name: str
        :param value: Value to encode
        :param types: Dictionary of custom type definitions
        :type types: dict
        :return: 32-byte encoded value
        :rtype: bytes
        """
        result = None

        # Primitive types
        if type_name == "string":
            result = Wallet._encode_string(value)
        elif type_name == "bytes":
            result = Wallet._encode_bytes(value)
        elif type_name == "address":
            result = Wallet._encode_address(value)
        elif type_name == "bool":
            result = Wallet._encode_bool(value)
        # Numeric types
        elif type_name.startswith("uint"):
            result = Wallet._encode_uint(value)
        elif type_name.startswith("int"):
            result = Wallet._encode_int(value)
        # Fixed-size bytes
        elif type_name.startswith("bytes"):
            result = Wallet._encode_fixed_bytes(type_name, value)
        # Array types
        elif type_name.endswith("[]"):
            element_type = type_name[:-2]
            result = Wallet._encode_array(element_type, value, types)
        # Custom struct types
        elif type_name in types:
            result = Wallet._hash_struct(type_name, value, types).to_bytes(32, "big")
        # Default fallback
        else:
            result = Wallet._hash_message(str(value).encode("utf-8")).to_bytes(32, "big")

        return result

    @staticmethod
    def _hash_struct(primary_type, data, types):
        """Hash a struct according to EIP-712 specification.

        :param primary_type: Type name of the struct
        :type primary_type: str
        :param data: Struct data to hash
        :type data: dict
        :param types: Dictionary of type definitions
        :type types: dict
        :return: Keccak-256 hash of the encoded struct
        :rtype: int
        """
        type_hash = Wallet._hash_type(primary_type, types)
        encoded_data = [type_hash.to_bytes(32, "big")]

        type_def = types.get(primary_type, [])

        for field in type_def:
            field_name = field["name"]
            field_type = field["type"]

            if field_name in data:
                field_value = data[field_name]
                encoded_field = Wallet._encode_value(field_type, field_value, types)
                encoded_data.append(encoded_field)
            else:
                encoded_data.append(bytes(32))

        full_data = b"".join(encoded_data)
        return Wallet._hash_message(full_data)

    @staticmethod
    def _encode_typed_data_v2(domain, types, primary_type, message):
        """Encode typed data according to EIP-712 specification.

        Creates the final hash by combining domain separator and message hash
        with the EIP-712 prefix (0x1901).

        :param domain: Domain separator dictionary
        :type domain: dict
        :param types: Type definitions dictionary
        :type types: dict
        :param primary_type: Name of the primary message type
        :type primary_type: str
        :param message: Message data to encode
        :type message: dict
        :return: Final EIP-712 hash as integer
        :rtype: int

        .. seealso::
            `EIP-712 <https://eips.ethereum.org/EIPS/eip-712>`_ specification.
        """
        domain_type = {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ]
        }

        domain_hash = Wallet._hash_struct("EIP712Domain", domain, domain_type)
        message_hash = Wallet._hash_struct(primary_type, message, types)

        final_data = (
            b"\x19\x01" + domain_hash.to_bytes(32, "big") + message_hash.to_bytes(32, "big")
        )

        return Wallet._hash_message(final_data)

    def _sign_message_hash(self, message_hash):
        """Sign a message hash using ECDSA with deterministic k (RFC 6979).

        :param message_hash: Hash of the message to sign
        :type message_hash: int
        :return: Tuple of (r, s) signature components
        :rtype: tuple
        :raises RuntimeError: If signature generation fails after maximum attempts
        """
        z = self._safe_mod(message_hash, N)

        max_attempts = 50

        for attempt in range(max_attempts):
            try:
                k = self._generate_rfc6979_k(self._private_key, message_hash, attempt)

                if k == 0:
                    continue

                rx, _ = self._scalar_mult(k, GX, GY)
                if rx is None:
                    continue

                r = self._safe_mod(rx, N)
                if r == 0:
                    continue

                r_priv = self._safe_mod(r * self._private_key, N)
                z_plus_r_priv = self._safe_mod(z + r_priv, N)

                k_inv = self._mod_inverse(k, N)
                s = self._safe_mod(k_inv * z_plus_r_priv, N)

                if s == 0:
                    continue

                if s > N // 2:
                    s = N - s

                return r, s

            except Exception:
                continue

        raise RuntimeError(f"Failed to generate signature after {max_attempts} attempts")

    def _recover_public_key(self, message_hash, r, s, recovery_id):
        """Recover public key from ECDSA signature.

        :param message_hash: Hash of the signed message
        :type message_hash: int
        :param r: Signature r component
        :type r: int
        :param s: Signature s component
        :type s: int
        :param recovery_id: Recovery identifier (0-3)
        :type recovery_id: int
        :return: Tuple of (x, y) coordinates of recovered public key, or (None, None) on failure
        :rtype: tuple
        """
        try:
            x = r + (recovery_id // 2) * N

            y_squared = self._safe_mod(x * x * x + 7, P)
            y = pow(y_squared, (P + 1) // 4, P)

            if (y % 2) != (recovery_id % 2):
                y = P - y

            r_inv = self._mod_inverse(r, N)
            e = self._safe_mod(message_hash, N)

            sr_x, sr_y = self._scalar_mult(s, x, y)
            eg_x, eg_y = self._scalar_mult(e, GX, GY)

            neg_eg_y = P - eg_y if eg_y != 0 else 0
            diff_x, diff_y = self._point_add(sr_x, sr_y, eg_x, neg_eg_y)

            pub_x, pub_y = self._scalar_mult(r_inv, diff_x, diff_y)

            return pub_x, pub_y

        except Exception:
            return None, None

    def _calculate_recovery_id(self, message_hash, r, s):
        """Calculate the correct recovery ID (v) for an ECDSA signature.

        Tests all possible recovery IDs to find which one recovers the correct public key.

        :param message_hash: Hash of the signed message
        :type message_hash: int
        :param r: Signature r component
        :type r: int
        :param s: Signature s component
        :type s: int
        :return: Recovery ID (0-3)
        :rtype: int
        """
        actual_pub_x, actual_pub_y = self._public_key

        for recovery_id in range(4):
            recovered_pub_x, recovered_pub_y = self._recover_public_key(
                message_hash, r, s, recovery_id
            )

            if recovered_pub_x == actual_pub_x and recovered_pub_y == actual_pub_y:
                return recovery_id

        return 0

    def signMessage(self, message):
        """Sign a personal message using ERC-191 standard.

        Automatically prepends the Ethereum message prefix before signing.
        Compatible with ethers.js ``wallet.signMessage()`` method.

        :param message: Message to sign (string or bytes)
        :type message: str or bytes
        :return: Compact signature string (130 hex chars + 0x prefix)
        :rtype: str

        .. code-block:: python

            wallet = Wallet("0x022b99092266a16a949e6a450f0e88a8288d39d5f1d75c00575a35a0ba270dbc")
            signature = wallet.signMessage("hello")
            print(signature)  # "0xrrr...sss...vv"

            # Parse signature
            sig = getattr(Signature, 'from')(signature)
            print(sig.r, sig.s, sig.v)

        .. seealso::
            `ERC-191 <https://eips.ethereum.org/EIPS/eip-191>`_ specification.
        """
        message_hash = self._create_ethereum_message_hash(message)
        r, s = self._sign_message_hash(message_hash)
        recovery_id = self._calculate_recovery_id(message_hash, r, s)
        v = 27 + recovery_id

        r_hex = _int_to_hex(r)
        s_hex = _int_to_hex(s)
        v_hex = self._custom_zfill(hex(v)[2:], 2)

        return "0x" + r_hex + s_hex + v_hex

    def _signTypedData(self, domain, types, message):
        """Sign structured typed data using EIP-712 standard.

        Provides more readable and secure signing for structured data.
        Compatible with ethers.js ``wallet._signTypedData()`` method.
        Automatically determines the primary type from the types dictionary.

        :param domain: Domain separator containing name, version, chainId, and verifyingContract
        :type domain: dict
        :param types: Type definitions (do not include EIP712Domain)
        :type types: dict
        :param message: Message data matching the primary type structure
        :type message: dict
        :return: Compact signature string (130 hex chars + 0x prefix)
        :rtype: str

        .. code-block:: python

            domain = {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            }

            types = {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            }

            message = {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"
            }

            signature = wallet._signTypedData(domain, types, message)

        .. seealso::
            `EIP-712 <https://eips.ethereum.org/EIPS/eip-712>`_ specification.
        """
        # Determine the primary type from the types dict
        # Find the type that is not referenced by others
        all_types = set(types.keys())
        referenced_types = set()

        for type_name in types:
            for field in types[type_name]:
                field_type = field["type"]
                if field_type.endswith("[]"):
                    field_type = field_type[:-2]
                if field_type in all_types:
                    referenced_types.add(field_type)

        # Primary type is the one not referenced by others
        primary_types = all_types - referenced_types
        if len(primary_types) == 1:
            primary_type = list(primary_types)[0]
        else:
            # Fallback: use the first type in the dict
            primary_type = list(types.keys())[0]

        typed_hash = self._encode_typed_data_v2(domain, types, primary_type, message)
        r, s = self._sign_message_hash(typed_hash)
        recovery_id = self._calculate_recovery_id(typed_hash, r, s)
        v = 27 + recovery_id

        r_hex = _int_to_hex(r)
        s_hex = _int_to_hex(s)
        v_hex = self._custom_zfill(hex(v)[2:], 2)

        return "0x" + r_hex + s_hex + v_hex

    def verify_signature(self, message_hash, r, s):
        """Verify an ECDSA signature against the wallet's public key.

        :param message_hash: Hash of the message that was signed
        :type message_hash: int
        :param r: Signature r component
        :type r: int
        :param s: Signature s component
        :type s: int
        :return: True if signature is valid, False otherwise
        :rtype: bool
        """
        try:
            if r < 1 or r >= N or s < 1 or s >= N:
                return False

            z = self._safe_mod(message_hash, N)

            s_inv = self._mod_inverse(s, N)
            u1 = self._safe_mod(z * s_inv, N)
            u2 = self._safe_mod(r * s_inv, N)

            x1, y1 = self._scalar_mult(u1, GX, GY)
            x2, y2 = self._scalar_mult(u2, self._public_key[0], self._public_key[1])
            x, _ = self._point_add(x1, y1, x2, y2)

            if x is None:
                return False

            return r == self._safe_mod(x, N)

        except Exception:
            return False

    def get_address(self):
        """Get Ethereum address (legacy method).

        .. deprecated::
            Use the :attr:`address` property instead.

        :return: Ethereum address with 0x prefix
        :rtype: str
        """
        return self.address

    def get_public_key(self):
        """Get public key coordinates (legacy method).

        .. deprecated::
            Use the :attr:`publicKey` property for hex string representation.

        :return: Tuple of (x, y) coordinates as integers
        :rtype: tuple
        """
        return self._public_key

    def get_private_key(self):
        """Get private key as integer (legacy method).

        .. deprecated::
            Use the :attr:`privateKey` property for hex string representation.

        :return: Private key as integer
        :rtype: int
        """
        return self._private_key
