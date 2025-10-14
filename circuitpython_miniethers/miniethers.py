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

__version__ = "0.0.0+auto.0"
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


class Wallet:
    """
    Ethereum wallet for CircuitPython
    Provides methods for signing messages and typed data, similar to ethers.js
    """

    def __init__(self, private_key=None):
        """
        Initialize wallet with optional private key

        Args:
            private_key: Integer private key or None to generate new one
        """
        if private_key is None:
            self._private_key = self._generate_private_key()
        else:
            if not (1 <= private_key < N):
                raise ValueError("Private key must be in range [1, N-1]")
            self._private_key = private_key

        self._public_key = self._derive_public_key()

    @staticmethod
    def _safe_mod(a, m):
        """Safe modulo operation to prevent overflow"""
        if a < 0:
            return (a % m + m) % m
        return a % m

    @staticmethod
    def _mod_inverse(a, m):
        """Extended Euclidean Algorithm for modular inverse"""
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
        """Double a point on secp256k1"""
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
        """Add two points on secp256k1"""
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
        """Multiply point by scalar using binary method"""
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
        """Generate deterministic k according to RFC 6979"""
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
        """Generate a random private key"""

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
        """Derive public key from private key"""
        return self._scalar_mult(self._private_key, GX, GY)

    @staticmethod
    def _hash_message(message):
        """Hash a message using Keccak256"""
        if isinstance(message, str):
            message = message.encode("utf-8")
        h = keccak.Keccak256(message)
        digest = h.digest()
        return int.from_bytes(digest, "big")

    @staticmethod
    def _create_ethereum_message_hash(message):
        """Create Ethereum signed message hash with prefix (ERC-191)"""
        if isinstance(message, str):
            message = message.encode("utf-8")

        prefix = b"\x19Ethereum Signed Message:\n"
        length = str(len(message)).encode("utf-8")
        full_message = prefix + length + message

        return Wallet._hash_message(full_message)

    def _sign_message_hash(self, message_hash):
        """Sign a message hash with private key using ECDSA"""
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
        """Recover public key from signature"""
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
        """Calculate the correct recovery ID (v) for the signature"""
        actual_pub_x, actual_pub_y = self._public_key

        for recovery_id in range(4):
            recovered_pub_x, recovered_pub_y = self._recover_public_key(
                message_hash, r, s, recovery_id
            )

            if recovered_pub_x == actual_pub_x and recovered_pub_y == actual_pub_y:
                return recovery_id

        return 0

    def sign_message(self, message):
        """
        Sign a personal message (ERC-191)

        Args:
            message: String or bytes to sign

        Returns:
            dict: {'r': hex string, 's': hex string, 'v': int}
        """
        message_hash = self._create_ethereum_message_hash(message)
        r, s = self._sign_message_hash(message_hash)
        recovery_id = self._calculate_recovery_id(message_hash, r, s)
        v = 27 + recovery_id

        return {"r": "0x" + self._int_to_hex(r), "s": "0x" + self._int_to_hex(s), "v": v}

    @staticmethod
    def _encode_type(primary_type, types):
        """Encode a struct type according to EIP-712"""
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
        """Find all type dependencies recursively"""
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
        """Hash a type string according to EIP-712"""
        type_string = Wallet._encode_type(primary_type, types)
        return Wallet._hash_message(type_string.encode("utf-8"))

    @staticmethod
    def _custom_ljust(data, width, fillchar=b"\x00"):
        """Left justify bytes"""
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
        """Right justify bytes"""
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
        """Zero fill string"""
        if len(s) >= width:
            return s
        return "0" * (width - len(s)) + s

    @staticmethod
    def _encode_value(type_name, value, types):
        """Encode a value according to its type"""
        if type_name == "string":
            if isinstance(value, str):
                return Wallet._hash_message(value.encode("utf-8")).to_bytes(32, "big")
            else:
                return Wallet._hash_message(str(value).encode("utf-8")).to_bytes(32, "big")

        elif type_name == "bytes":
            if isinstance(value, str):
                if value.startswith("0x"):
                    return Wallet._hash_message(bytes.fromhex(value[2:])).to_bytes(32, "big")
                else:
                    return Wallet._hash_message(value.encode("utf-8")).to_bytes(32, "big")
            else:
                return Wallet._hash_message(value).to_bytes(32, "big")

        elif type_name.startswith("bytes"):
            if isinstance(value, str) and value.startswith("0x"):
                hex_value = value[2:]
                size = int(type_name[5:]) if len(type_name) > 5 else 32
                hex_value = Wallet._custom_zfill(hex_value, size * 2)[: size * 2]
                return Wallet._custom_ljust(bytes.fromhex(hex_value), 32, b"\x00")
            else:
                return Wallet._custom_ljust(str(value).encode("utf-8"), 32, b"\x00")[:32]

        elif type_name == "address":
            if isinstance(value, str):
                if value.startswith("0x"):
                    addr_hex = value[2:]
                else:
                    addr_hex = value
                addr_hex = Wallet._custom_zfill(addr_hex.lower(), 40)
                return Wallet._custom_rjust(bytes.fromhex(addr_hex), 32, b"\x00")
            else:
                return bytes(32)

        elif type_name.startswith("uint"):
            if isinstance(value, str):
                if value.startswith("0x"):
                    num_value = int(value, 16)
                else:
                    num_value = int(value)
            else:
                num_value = int(value)
            return num_value.to_bytes(32, "big")

        elif type_name.startswith("int"):
            if isinstance(value, str):
                if value.startswith("0x"):
                    num_value = int(value, 16)
                else:
                    num_value = int(value)
            else:
                num_value = int(value)

            if num_value < 0:
                num_value = (1 << 256) + num_value

            return num_value.to_bytes(32, "big")

        elif type_name == "bool":
            bool_value = bool(value)
            return (1 if bool_value else 0).to_bytes(32, "big")

        elif type_name.endswith("[]"):
            element_type = type_name[:-2]
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

        elif type_name in types:
            return Wallet._hash_struct(type_name, value, types).to_bytes(32, "big")

        else:
            return Wallet._hash_message(str(value).encode("utf-8")).to_bytes(32, "big")

    @staticmethod
    def _hash_struct(primary_type, data, types):
        """Hash a struct according to EIP-712"""
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
        """Enhanced EIP-712 typed data encoding"""
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

    def sign_typed_data(self, domain, types, primary_type, message):
        """
        Sign typed data using EIP-712 standard

        Args:
            domain: Domain separator dict
            types: Type definitions dict
            primary_type: Name of the primary type
            message: Message data dict

        Returns:
            dict: {'r': hex string, 's': hex string, 'v': int}
        """
        typed_hash = self._encode_typed_data_v2(domain, types, primary_type, message)
        r, s = self._sign_message_hash(typed_hash)
        recovery_id = self._calculate_recovery_id(typed_hash, r, s)
        v = 27 + recovery_id

        return {"r": "0x" + self._int_to_hex(r), "s": "0x" + self._int_to_hex(s), "v": v}

    def verify_signature(self, message_hash, r, s):
        """
        Verify ECDSA signature

        Args:
            message_hash: Hash of the message
            r: Signature r value
            s: Signature s value

        Returns:
            bool: True if signature is valid
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
        """
        Get Ethereum address from public key

        Returns:
            str: Hex formatted Ethereum address
        """
        pub_x, pub_y = self._public_key
        concat_x_y = pub_x.to_bytes(32, "big") + pub_y.to_bytes(32, "big")
        eth_address = keccak.Keccak256(concat_x_y).digest()[-20:]
        return "0x" + binascii.hexlify(eth_address).decode()

    def get_public_key(self):
        """
        Get public key

        Returns:
            tuple: (x, y) coordinates as integers
        """
        return self._public_key

    def get_private_key(self):
        """
        Get private key

        Returns:
            int: Private key
        """
        return self._private_key

    @staticmethod
    def _int_to_hex(num, length=64):
        """Convert integer to hex string with padding"""
        try:
            hex_str = hex(num)[2:]
            return Wallet._custom_zfill(hex_str, length)
        except Exception:
            return "0" * length
