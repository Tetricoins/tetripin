import getpass
import re

import secrets
from typing import Union
import keyring
from path import Path
import toml
from cryptography.fernet import Fernet

from tetripin.exceptions import TetripinError
from appdirs import user_data_dir
import logging
import base64


from cryptography.fernet import Fernet
from typing_extensions import Self

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

log = logging.getLogger(__name__)

DATA_DIR = user_data_dir("tetripin", "tetricoins", version="0.1")


class EncryptionKey:
    """Convenience wrapper on top of Fernet primitives"""

    def __init__(self, value):
        self.bytes = value
        self.fernet = Fernet(value)

    @classmethod
    def from_string(cls, value) -> Self:
        return cls(cls._from_utf8(value))

    @classmethod
    def from_password(cls, password: str, salt: str) -> Self:
        """Derive an encryption key from a password and a salt

        Password must be the value as typed as the user, salt must be
        a base64 encoded number
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(salt),
            iterations=480000,
        )
        value = base64.urlsafe_b64encode(kdf.derive(cls._to_utf8(password)))

        return cls(value)

    def __str__(self):
        return self._from_utf8(self.bytes)

    @staticmethod
    def _to_utf8(text) -> bytes:
        return text.encode("utf8", errors="surrogateescape")

    @staticmethod
    def _from_utf8(bytes) -> str:
        return bytes.decode("utf8", errors="surrogateescape")

    def encrypt_to_text(self, text) -> str:
        return self._from_utf8(self.fernet.encrypt(self._to_utf8(text)))

    def decrypt_from_text(self, text) -> str:
        return self._from_utf8(self.fernet.decrypt(self._to_utf8(text)))


def prompt_password(prompt: str) -> str:
    print(prompt)

    while True:
        password1 = getpass.getpass("Enter your password: ")
        password2 = getpass.getpass("Re-enter your password: ")

        if password1 == password2:
            break

        print("Passwords do not match. Please try again.")

    return password1


def get_key_from_keyring() -> Union[EncryptionKey, None]:
    key = keyring.get_password("tetripin", "key")

    if key:
        return EncryptionKey(key)


def ensure_secrets_file(data_dir=None, secrets_file=None):
    # Try to get a setting dir
    if data_dir:
        data_dir = Path(data_dir)
        if not data_dir.isdir():
            log.info("Setting dir does not exist. Attempting to create one.")
            try:
                data_dir.makedirs_p()
            except (OSError, IOError) as ex:
                raise TetripinError(f'Unable to create settings dir "{data_dir}": {ex}')

    # Try to get a secrets file
    if not secrets_file:
        if not data_dir:
            raise TetripinError(
                "You need to provide a path to the secrets file. "
                "Either allow the one from the settings dir to be used, "
                "set TETRIPIN_SECRETS or pass --secrets-file"
            )
        else:
            secrets_file = data_dir / "secrets.toml"
            try:
                # generate an empty file
                if not secrets_file.isfile():
                    with secrets_file.open("a", encoding="utf8") as f:
                        toml.dump(
                            {
                                "format_version": 2,
                                "account": {},
                                "salt": secrets.token_bytes(16),
                            },
                            f,
                        )
                else:  # update the access time
                    with secrets_file.open("a", encoding="utf8") as f:
                        secrets_file.utime(None)
            except (OSError, IOError) as ex:
                raise TetripinError(
                    f'Unable to open the secrets file "{secrets_file}": {ex}'
                )
            except UnicodeDecodeError:
                raise TetripinError(
                    f'Unable to open the secrets file "{secrets_file}": it must be UTF8'
                )

    return secrets_file


def load_secrets_from_toml(secrets_file):
    try:
        with open(secrets_file, encoding="utf8") as f:
            data = toml.load(f)
    except (OSError, IOError) as ex:
        raise TetripinError(f'Unable to open the secrets file "{secrets_file}": {ex}')

    # Handle bad TOML
    except toml.TomlDecodeError as ex:
        msg = f"'{secrets_file}' is not a valid TOML file (Error given is: {ex})\n"
        error = ex.args[0]
        if error == "Invalid date or number":
            msg += (
                "One frequent cause of this is forgetting to put quotes "
                "around secret keys. Check the file."
            )
        # TODO: ask the toml guy to put a better error catching system in place
        match = re.search(r"What\? (\w+) ", error)
        duplicate = match and next(iter(match.groups()), None)
        if duplicate:
            msg += (
                "One frequent cause of this is using the same account name "
                f"twice. Check that you didn't use '{duplicate}' several times."
            )

        raise TetripinError(msg)

    except UnicodeDecodeError:
        raise TetripinError(
            f'Unable to open the secrets file "{secrets_file}": it must be UTF8'
        )

    if "format_version" not in data:
        raise TetripinError(
            f'Version is missing from the secrets file "{secrets_file}"'
        )

    if "account" not in data:
        raise TetripinError(
            f'"account" section is missing from the secrets file "{secrets_file}"'
        )

    return data


def build_secret_map_from_toml(key: Union[EncryptionKey, None], secrets_file):
    secrets_map = {}
    data = load_secrets_from_toml(secrets_file)

    for label, infos in data["account"].items():
        label = label.lower().strip()
        if label:
            secret = infos.get("secret", "").strip()
            if not secret:
                raise TetripinError(f"Account '{label}' don't have a secret.")

            if key:
                secret = key.decrypt_from_text(secret)

            secrets_map[label] = secret

    return secrets_map
