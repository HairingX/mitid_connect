"""The SRP-6a exchange and AES-GCM encryption MitID's browser client speaks."""

import base64
import secrets
import binascii
import hashlib
from collections.abc import Callable
from typing import Protocol, cast

from Cryptodome.Cipher import AES
from Cryptodome import Random

BLOCK_SIZE = 16


class _Gcm(Protocol):
    def encrypt_and_digest(self, plaintext: bytes) -> tuple[bytes, bytes]: ...
    def decrypt_and_verify(self, ciphertext: bytes, received_mac_tag: bytes) -> bytes: ...


# pycryptodomex annotates AES.new with a bare Dict among its overloads, which a strict check reads
# as unknown; it is taken by name, with the type it has in GCM mode.
_new_gcm = cast(Callable[[bytes, int, bytes], _Gcm], getattr(AES, "new"))


def pad(s: str) -> str:
    """`s` padded to a whole number of blocks, PKCS#7 style."""
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


def unpad(s: str) -> str:
    """`s` with its PKCS#7 padding taken off."""
    return s[:-ord(s[len(s) - 1:])]


def int_to_hex(x: int) -> str:
    """`x` in lower-case hex, without a prefix."""
    return format(x, 'x')


def int_to_bytes(x: int) -> bytes:
    """`x` as big-endian bytes, as few as hold it."""
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def bytes_to_int(x: bytes) -> int:
    """The big-endian number `x` holds."""
    return int.from_bytes(x, 'big')


def bytes_to_hex(x: bytes) -> str:
    """`x` in lower-case hex."""
    return binascii.hexlify(x).decode('utf-8')


def hex_to_bytes(x: str) -> bytes:
    """The bytes the hex `x` spells."""
    return binascii.unhexlify(x)


def hex_to_int(x: str) -> int:
    """The number the hex `x` spells."""
    return int(x, 16)


def AesDecryptWithKey(encMessage: str | bytes, key: bytes) -> bytes:
    """The plain text of the base64 AES-GCM message `encMessage`: IV, cipher text, then tag."""
    encMessage = base64.b64decode(encMessage)

    iv = encMessage[:BLOCK_SIZE]
    cipherText = encMessage[BLOCK_SIZE:len(encMessage)-BLOCK_SIZE]
    macTag = encMessage[len(encMessage)-BLOCK_SIZE:]

    cipher = _new_gcm(key, AES.MODE_GCM, iv)
    decrypted = cipher.decrypt_and_verify(cipherText, macTag)
    return decrypted

class CustomSRP():
    """One SRP-6a exchange with MitID, and the session key it agrees."""

    n: int
    g: int
    a: int
    big_a: int
    big_b: int
    hashed_password: int
    K_bits: bytes
    M1_hex: str

    def SRPStage1(self) -> str:
        """Pick a secret, and give the public value A, in hex, to send."""
        self.n = 4983313092069490398852700692508795473567251422586244806694940877242664573189903192937797446992068818099986958054998012331720869136296780936009508700487789962429161515853541556719593346959929531150706457338429058926505817847524855862259333438239756474464759974189984231409170758360686392625635632084395639143229889862041528635906990913087245817959460948345336333086784608823084788906689865566621015175424691535711520273786261989851360868669067101108956159530739641990220546209432953829448997561743719584980402874346226230488627145977608389858706391858138200618631385210304429902847702141587470513336905449351327122086464725143970313054358650488241167131544692349123381333204515637608656643608393788598011108539679620836313915590459891513992208387515629240292926570894321165482608544030173975452781623791805196546326996790536207359143527182077625412731080411108775183565594553871817639221414953634530830290393130518228654795859
        self.g = 2
        a = secrets.randbits(256)
        if a < 0:
            a += self.n
        self.a = a

        self.big_a = pow(self.g, self.a, self.n)
        return int_to_hex(self.big_a)
    
    def computeLittleS(self) -> int:
        """The multiplier k of SRP-6a, as MitID works it out."""
        N_bytes = int_to_bytes(self.n)
        g_bytes = int_to_bytes(self.g)
        
        # Prepend g_bytes with |N_bytes|-|g_bytes| of 0
        g_bytes = (b"\0" * (len(N_bytes) - len(g_bytes))) + g_bytes

        m = hashlib.sha256()
        m.update(str(self.n).encode('utf-8') + g_bytes)
        digest = m.hexdigest()

        return hex_to_int(digest)

    def computeU(self) -> int:
        """The scrambler u, from A and B."""
        N_length = len(int_to_bytes(self.n))
        A_bytes = int_to_bytes(self.big_a)
        B_bytes = int_to_bytes(self.big_b)

        # Prepend A_bytes with |N_bytes|-|A_bytes| of 0
        A_bytes = (b"\0"*(N_length-len(A_bytes)))+A_bytes

        # Prepend r_bytes with |N_bytes|-|r_bytes| of 0
        B_bytes = (b"\0"*(N_length-len(B_bytes)))+B_bytes
        
        m = hashlib.sha256()
        m.update(A_bytes + B_bytes)
        hashed = m.hexdigest()
        u = hex_to_int(hashed) % self.n
        return u

    def computeSessionKey(self) -> int:
        """The premaster secret S. MitID's own app does not refuse u == 0, so this does not."""
        u = self.computeU()

        s = self.computeLittleS()
        
        a = u * self.hashed_password + self.a
        c = pow((self.big_b - (pow(self.g, self.hashed_password, self.n) * s)), a, self.n)
        if a < 0:
            a += self.n

        return c

    def computeM1(self, r: str, srpSalt: str) -> str:
        """The client's proof M1, in hex."""
        m = hashlib.sha256()
        m.update(str(self.n).encode("utf-8"))
        N = hex_to_int(m.hexdigest())

        m = hashlib.sha256()
        m.update(str(self.g).encode("utf-8"))
        g = hex_to_int(m.hexdigest())
        a = N ^ g

        m = hashlib.sha256()
        m.update((str(a) + r + srpSalt + str(self.big_a) + str(self.big_b) + bytes_to_hex(self.K_bits)).encode("ascii"))
        return m.hexdigest()

    def SRPStage3(self, srpSalt: str, randomB: str, password: str, auth_session_id: str) -> str:
        """Take the server's B, agree the session key, and give the proof M1 to send.

        Raises:
            Exception: B fails SRP's safety check.
        """
        self.big_b = hex_to_int(randomB)

        if(self.big_b == 0 or self.big_b % self.n == 0):
            raise Exception("randomB did not pass safety check")

        m = hashlib.sha256()
        m.update((srpSalt + password).encode("ascii"))
        self.hashed_password = hex_to_int(m.hexdigest())

        a = self.computeSessionKey()

        m = hashlib.sha256()
        m.update(str(a).encode("utf-8"))
        self.K_bits = m.digest()

        m = hashlib.sha256()
        m.update(auth_session_id.encode("utf-8"))
        I_hex = m.hexdigest()

        self.M1_hex = self.computeM1(I_hex, srpSalt)

        return self.M1_hex
    
    # Should satisfy if the server is correct
    # Interestingly enough, this cannot be checked for the pin-binding proof
    def SRPStage5(self, M2_hex: str) -> bool:
        """Whether the server's proof M2 matches the session key agreed."""
        M1_bigInt = int(self.M1_hex, 16)

        m = hashlib.sha256()
        m.update((str(self.big_a) + str(M1_bigInt) + bytes_to_hex(self.K_bits)).encode('utf-8'))
        M2_hex_verify = m.hexdigest()
        return M2_hex_verify == M2_hex

    def AuthEnc(self, plainText: bytes) -> bytes:
        """`plainText` encrypted with the session key: IV, cipher text, then tag."""
        iv = Random.new().read(BLOCK_SIZE)
        cipher = _new_gcm(self.K_bits, AES.MODE_GCM, iv)
        ciphertext, tag = cipher.encrypt_and_digest(plainText)
        return (iv + ciphertext + tag)

    def AuthDec(self, encMessage: str | bytes) -> bytes:
        """The plain text of a message encrypted with the session key."""
        return AesDecryptWithKey(encMessage, self.K_bits)
    
    def AuthDecPin(self, encMessage: str | bytes) -> bytes:
        """The plain text of a message encrypted with the PIN key derived from the session key."""
        pin_key = hashlib.sha256(binascii.hexlify(self.K_bits) + b"PIN").digest()
        return AesDecryptWithKey(encMessage, pin_key)
