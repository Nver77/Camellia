import sys

from binascii import unhexlify

from pep272_encryption import PEP272Cipher

from ._camellia import lib, ffi  # pylint: disable=import-error

# pylint: disable=invalid-name


#: ECB mode of operation
MODE_ECB = 1
#: CBC mode of operation
MODE_CBC = 2
#: CFB mode of operation
MODE_CFB = 3
#: OFB mode of operation
MODE_OFB = 5
#: CTR mode of operation
MODE_CTR = 6


if sys.version_info.major <= 2:
    def b(_b):
        """Create bytes from a list of ints."""
        return "".join(map(chr, _b))


else:
    b = bytes


_selftest_vectors = (
    (
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
    ),
    (
        "0123456789abcdeffedcba98765432100011223344556677",
        "0123456789abcdeffedcba9876543210",
        "b4993401b3e996f84ee5cee7d79b09b9",
    ),
    (
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "0123456789abcdeffedcba9876543210",
        "9acc237dff16d76c20ef7c919e3a7509",
    ),
)


def _check_keylength(length):
    if length not in [128, 192, 256]:
        raise ValueError(
            "Invalid key length, " "it must be 128, 192 or 256 bits long!"
        )


def _check_blocksize(string):
    if len(string) % block_size:
        raise ValueError("Input must be a multiple of 16 in length")


def Camellia_Ekeygen(rawKey):

    key_length = len(rawKey) * 8

    _check_keylength(key_length)

    keytable = ffi.new("KEY_TABLE_TYPE")

    lib.Camellia_Ekeygen(key_length, rawKey, keytable)

    return list(keytable)


def Camellia_Encrypt(keyLength, keytable, plainText):

    _check_keylength(keyLength)

    if len(plainText) != 16:
        raise ValueError("Plain text length must be 16!")

    out = b"\x00" * 16

    lib.Camellia_EncryptBlock(keyLength, plainText, keytable, out)

    return out


def Camellia_Decrypt(keyLength, keytable, cipherText):

    _check_keylength(keyLength)

    if len(cipherText) != 16:
        raise ValueError("Cipher text length must be 16!")

    out = b"\x00 " *block_size

    lib.Camellia_DecryptBlock(keyLength, cipherText, keytable, out)

    return out


def new(key, mode, IV=None, **kwargs):

    return CamelliaCipher(key, mode, IV=IV, **kwargs)


key_size = None
block_size = 16


class CamelliaCipher(PEP272Cipher):

    block_size = 16

    @property
    def IV(self):
        if self.mode in (MODE_ECB, MODE_CTR):
            return None
        if self.mode == MODE_CBC:
            return bytes(self._status_buffer)
        return super(CamelliaCipher, self).IV

    def __init__(self, key, mode, **kwargs):
        """Constructer of Cipher class. See :func:`camellia.new`."""
        keytable = Camellia_Ekeygen(key)
        self.key_length = len(key) * 8

        iv = kwargs.get('IV', kwargs.get('iv'))
        if iv is not None:
            # Force copy, IV may be interned or used elsewhere
            self._status_buffer = \
                ffi.new("unsigned char [CAMELLIA_BLOCK_SIZE]",
                        iv)

        PEP272Cipher.__init__(self, keytable, mode, **kwargs)

    def encrypt(self, string):


        if self.mode == MODE_ECB or self.mode == MODE_CBC:
            _check_blocksize(string)

        if self.mode == MODE_ECB:
            return self._encrypt_ecb_fast(string)

        if self.mode == MODE_CBC:
            return self._encrypt_cbc_fast(string)

        return super(CamelliaCipher, self).encrypt(string)

    def decrypt(self, string):

        if self.mode == MODE_ECB or self.mode == MODE_CBC:
            _check_blocksize(string)

        if self.mode == MODE_ECB:
            return self._decrypt_ecb_fast(string)

        if self.mode == MODE_CBC:
            return self._decrypt_cbc_fast(string)

        return super(CamelliaCipher, self).encrypt(string)

    def encrypt_block(self, key, block, **kwargs):
        """Encrypt a single block with camellia."""
        return Camellia_Encrypt(self.key_length, key, block)

    def decrypt_block(self, key, block, **kwargs):
        """Decrypt a single block with camellia."""
        return Camellia_Decrypt(self.key_length, key, block)

    def _encrypt_ecb_fast(self, string):
        cipher_text = b"\x00" * len(string)
        lib.Camellia_EncryptEcb(
            self.key_length,
            string,
            self.key,
            cipher_text,
            len(string) // 16
        )
        return cipher_text

    def _decrypt_ecb_fast(self, string):
        plain_text = b"\x00" * len(string)
        lib.Camellia_DecryptEcb(
            self.key_length,
            string,
            self.key,
            plain_text,
            len(string) // 16
        )
        return plain_text

    def _encrypt_cbc_fast(self, string):
        cipher_text = b"\x00" * len(string)
        lib.Camellia_EncryptCbc(
            self.key_length,
            string,
            self.key,
            cipher_text,
            len(string) // 16,
            self._status_buffer
        )
        return cipher_text

    def _decrypt_cbc_fast(self, string):
        plain_text = b"\x00" * len(string)
        lib.Camellia_DecryptCbc(
            self.key_length,
            string,
            self.key,
            plain_text,
            len(string) // 16,
            self._status_buffer
        )
        return plain_text


def self_test():
    """
    Run self-test.

    :raises RuntimeError:
    """
    for key, plain_hex, cipher_hex in _selftest_vectors:
        cam = new(unhexlify(key), MODE_ECB)
        plain, cipher = unhexlify(plain_hex), unhexlify(cipher_hex)
        if cam.encrypt(plain) != cipher or cam.decrypt(cipher) != plain:
            raise RuntimeError("Self-test of camellia failed")


self_test()
