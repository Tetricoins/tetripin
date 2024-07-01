import re


import keyring
from path import Path
import toml
from cryptography.fernet import Fernet

from tetripin.exceptions import TetripinError
from appdirs import user_data_dir
import logging

log = logging.getLogger(__name__)

DATA_DIR = user_data_dir("tetripin", "tetricoins", version="0.1")


def encrypt_ascii_text(key, text):
    return key.encrypt(text.encode("ascii")).decode("ascii")


def ensure_key():
    # todo: use surrogate escape on the key
    if not (key := keyring.get_password("tetripin", "key")):
        log.info("This is a new setup. Creating a new encryption key")
        key = Fernet.generate_key()
        keyring.set_password("tetripin", "key", key)

    return Fernet(key)


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
                        toml.dump({"format_version": 2, "account": {}}, f)
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


def build_secret_map_from_toml(key, secrets_file):
    secrets_map = {}
    data = load_secrets_from_toml(secrets_file)

    for label, infos in data["account"].items():
        label = label.lower().strip()
        if label:
            secret = infos.get("secret", "").strip()
            if not secret:
                raise TetripinError(f"Account '{label}' don't have a secret.")

            if data["format_version"] > 1:
                secret = key.decrypt(secret.encode("ascii")).decode("ascii")

            secrets_map[label] = secret

    return secrets_map
