from __future__ import annotations

import abc
from hashlib import sha1


class Key(metaclass=abc.ABCMeta):
    """
    Interface for a public or private key.
    """

    @abc.abstractmethod
    def pub(self) -> PublicKey:
        """
        Return the public key for this key material.
        """

    @abc.abstractmethod
    def has_secret_key(self) -> bool:
        """
        Whether this key material includes a secret key.

        Public keys MAY also contain a private key but not the other way around.
        """

    @abc.abstractmethod
    def key_to_bin(self) -> bytes:
        """
        Convert this key material to bytes.
        """

    def key_to_hash(self) -> bytes:
        """
        Get the SHA-1 hash of this key.
        """
        if self.has_secret_key():
            return sha1(self.pub().key_to_bin()).digest()
        return sha1(self.key_to_bin()).digest()


class PrivateKey(Key, metaclass=abc.ABCMeta):
    """
    Interface for a private key.
    """

    def has_secret_key(self) -> bool:
        """
        A private key is the secret key, always True.
        """
        return True

    @abc.abstractmethod
    def signature(self, msg: bytes) -> bytes:
        """
        Create a signature for the given data.
        """


class PublicKey(Key, metaclass=abc.ABCMeta):
    """
    Interface for a public key.
    """

    def pub(self) -> PublicKey:
        """
        We are already the public key, return ourselves.
        """
        return self

    def has_secret_key(self) -> bool:
        """
        By default, a public key cannot be assumed to include private key material.
        """
        return False

    @abc.abstractmethod
    def verify(self, signature: bytes, msg: bytes) -> bool:
        """
        Verify that the given signature belongs to the given message for this public key.
        """

    @abc.abstractmethod
    def get_signature_length(self) -> int:
        """
        Get the length (in number of bytes) for signatures generated by this type of key.
        """
