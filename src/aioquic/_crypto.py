from typing import Tuple

from cryptography.hazmat.bindings.openssl.binding import Binding

AEAD_KEY_LENGTH_MAX = 32
AEAD_NONCE_LENGTH = 12
AEAD_TAG_LENGTH = 16

PACKET_LENGTH_MAX = 1500


class CryptoError(ValueError):
    pass


def _get_cipher_by_name(binding: Binding, cipher_name: bytes):  # -> EVP_CIPHER
    evp_cipher = binding.lib.EVP_get_cipherbyname(cipher_name)
    if evp_cipher == binding.ffi.NULL:
        raise CryptoError(f"Invalid cipher name: {cipher_name.decode()}")
    return evp_cipher


class AEAD:
    def __init__(self, cipher_name: bytes, key: bytes, iv: bytes) -> None:
        self._binding = Binding()
        self._evp_cipher = _get_cipher_by_name(self._binding, cipher_name)
        if len(key) > AEAD_KEY_LENGTH_MAX:
            raise CryptoError("Invalid key length")
        self._key = key
        if len(iv) > AEAD_NONCE_LENGTH:
            raise CryptoError("Invalid iv length")
        self._iv = iv
        self._decrypt_ctx = self._create_ctx(0)
        self._encrypt_ctx = self._create_ctx(1)
        # allocate buffers
        self._nonce = bytearray(AEAD_NONCE_LENGTH)
        self._buffer = self._binding.ffi.new("unsigned char[]", PACKET_LENGTH_MAX)
        self._outlen = self._binding.ffi.new("int *")
        self._dummy_outlen = self._binding.ffi.new("int *")

    def _create_ctx(self, operation: int):  # -> EVP_CIPHER_CTX
        ctx = self._binding.lib.EVP_CIPHER_CTX_new()
        ctx = self._binding.ffi.gc(ctx, self._binding.lib.EVP_CIPHER_CTX_free)
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                ctx,
                self._evp_cipher,
                self._binding.ffi.NULL,
                self._binding.ffi.NULL,
                self._binding.ffi.NULL,
                operation,
            )
        )
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_set_key_length(ctx, len(self._key))
        )
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_ctrl(
                ctx,
                self._binding.lib.EVP_CTRL_AEAD_SET_IVLEN,
                AEAD_NONCE_LENGTH,
                self._binding.ffi.NULL,
            )
        )
        return ctx

    def _assert(self, value) -> None:
        if not value:
            self._binding.lib.ERR_clear_error()
            raise CryptoError("OpenSSL call failed")

    def _init_nonce(self, packet_number: int) -> None:
        self._nonce[0 : len(self._iv)] = self._iv
        for i in range(8):
            self._nonce[AEAD_NONCE_LENGTH - 1 - i] ^= packet_number >> 8 * i

    def decrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        if len(data) < AEAD_TAG_LENGTH or len(data) > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._init_nonce(packet_number)
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_ctrl(
                self._decrypt_ctx,
                self._binding.lib.EVP_CTRL_AEAD_SET_TAG,
                AEAD_TAG_LENGTH,
                data[(len(data) - AEAD_TAG_LENGTH) :],
            )
        )
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                self._decrypt_ctx,
                self._binding.ffi.NULL,
                self._binding.ffi.NULL,
                self._key,
                self._nonce,
                0,
            )
        )
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._decrypt_ctx,
                self._binding.ffi.NULL,
                self._dummy_outlen,
                associated_data,
                len(associated_data),
            )
        )
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._decrypt_ctx,
                self._buffer,
                self._outlen,
                data,
                len(data) - AEAD_TAG_LENGTH,
            )
        )
        if not self._binding.lib.EVP_CipherFinal_ex(
            self._decrypt_ctx,
            self._binding.ffi.NULL,
            self._dummy_outlen,
        ):
            raise CryptoError("Payload decryption failed")
        return self._binding.ffi.buffer(self._buffer, self._outlen[0])[:]

    def encrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        if len(data) > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._init_nonce(packet_number)
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                self._encrypt_ctx,
                self._binding.ffi.NULL,
                self._binding.ffi.NULL,
                self._key,
                self._nonce,
                1,
            )
        )
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._encrypt_ctx,
                self._binding.ffi.NULL,
                self._dummy_outlen,
                associated_data,
                len(associated_data),
            )
        )
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._encrypt_ctx,
                self._buffer,
                self._outlen,
                data,
                len(data),
            )
        )
        self._assert(
            self._binding.lib.EVP_CipherFinal_ex(
                self._encrypt_ctx,
                self._binding.ffi.NULL,
                self._dummy_outlen,
            )
            and self._dummy_outlen[0] == 0
        )
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_ctrl(
                self._encrypt_ctx,
                self._binding.lib.EVP_CTRL_AEAD_GET_TAG,
                AEAD_TAG_LENGTH,
                self._buffer + self._outlen[0],
            )
        )
        return self._binding.ffi.buffer(
            self._buffer, self._outlen[0] + AEAD_TAG_LENGTH
        )[:]


class HeaderProtection:
    def __init__(self, cipher_name: bytes, key: bytes):
        self._binding = Binding()
        # allocate buffers
        self._buffer = self._binding.ffi.new("unsigned char[]", PACKET_LENGTH_MAX)
        self._mask = self._binding.ffi.new("unsigned char[]", 31)
        self._zero = self._binding.ffi.new("unsigned char[]", 5)

    def apply(self, plain_header: bytes, protected_payload: bytes) -> bytes:
        ...

    def remove(self, packet: bytes, encrypted_offset: int) -> Tuple[bytes, int]:
        ...
