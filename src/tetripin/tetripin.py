import re
from typing import Tuple, TypedDict
import pyotp
import keyring
import json

import datetime as dt
from path import Path
from appdirs import user_data_dir

import toml
import click

from cryptography.fernet import Fernet

DATA_DIR = user_data_dir("tetripin", "tetricoins", version="0.1")


def encrypt_ascii_text(key, text):
    return key.encrypt(text.encode("ascii")).decode("ascii")


def get_toml_data(ctx, secrets_file):
    try:
        with open(secrets_file, encoding="utf8") as f:
            data = toml.load(f)
    except (OSError, IOError) as ex:
        ctx.fail(f'Unable to open the secrets file "{secrets_file}": {ex}')

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

        ctx.fail(msg)

    except UnicodeDecodeError:
        ctx.fail(f'Unable to open the secrets file "{secrets_file}": it must be UTF8')

    else:
        if "format_version" not in data:
            ctx.fail(f'Version is missing from the secrets file "{secrets_file}"')

        if "account" not in data:
            ctx.fail(
                f'"account" section is missing from the secrets file "{secrets_file}"'
            )

        return data

    raise ValueError("Unable to parse the secrets file")


def get_secrets(ctx, secrets_file):
    """Parse TOML file and return secrets"""
    secrets_map = {}
    data = get_toml_data(ctx, secrets_file)

    # Load values from the file and handle missing ones
    for label, infos in data["account"].items():
        label = label.lower().strip()
        if label:
            secret = infos.get("secret", "").strip()
            if not secret:
                click.fail(f"Account '{label}' don't have a secret.")

            if data["format_version"] > 1:
                secret = ctx.obj["key"].decrypt(secret.encode("ascii")).decode("ascii")

            secrets_map[label] = secret

    return secrets_map


@click.group(name="tetripin")
@click.option("--secrets-file", help="Path to the toml files containing the secrets.")
@click.option(
    "--data-dir",
    default=DATA_DIR,
    help="Path to settings directory. Set to an empty string to ignore it.",
)

@click.pass_context
def cli(ctx, secrets_file, data_dir):
    """2FA code manager"""

    if not (key := keyring.get_password("tetripin", "key")):
        click.echo("This is a new setup. Creating a new encryption key")
        key = Fernet.generate_key()
        keyring.set_password("tetripin", "key", key)

    ctx.obj = {"key": Fernet(key)}

    # Try to get a setting dir
    if data_dir:
        data_dir = Path(data_dir)
        if not data_dir.isdir():
            click.echo("Setting dir does not exist. Attempting to create one.")
            try:
                data_dir.makedirs_p()
            except (OSError, IOError) as ex:
                msg = f'Unable to create settings dir "{data_dir}": {ex}'
                click.echo(click.style(msg, fg="red", err=True))
                data_dir = None

    # Try to get a secrets file
    if not secrets_file:
        if not data_dir:
            ctx.fail(
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
                ctx.fail(f'Unable to open the secrets file "{secrets_file}": {ex}')
            except UnicodeDecodeError:
                ctx.fail(
                    f'Unable to open the secrets file "{secrets_file}": it must be UTF8'
                )

    # if we use the old clear text format, attempt to convert it to the encrypted format
    data = get_toml_data(ctx, secrets_file)
    enrypted_data = {
        "format_version": 2,
        "account": {},
    }
    if data["format_version"] == 1:
        if click.confirm(
            "You have an old encrypted config file. Convert to the new encrypted format?",
            default=True,
        ):
            click.echo("Converting to the new format...")
            secrets_map = get_secrets(ctx, secrets_file)

            for account, secret in secrets_map.items():
                enrypted_data["account"][account] = {
                    "secret": encrypt_ascii_text(ctx.obj["key"], secret)
                }

            with secrets_file.open("w", encoding="utf8") as f:
                toml.dump(enrypted_data, f)

            click.echo("Your secrets are now encrypted using your OS keyring.")

    ctx.obj["data_dir"] = data_dir
    ctx.obj["secrets_file"] = secrets_file


@cli.command()
@click.pass_context
def listconfig(ctx):
    """Print informations about the program conf"""
    for name, value in ctx.obj.items():
        if name != "key":
            click.echo(f"{name}={value}")


@cli.command()
@click.pass_context
def listsecrets(ctx):
    """Print all the accounts and their secrets"""
    secrets_map = get_secrets(ctx, ctx.obj["secrets_file"])
    for name, value in secrets_map.items():
        click.echo(f"{name}={value}")


@cli.command()
@click.argument("account")
@click.pass_context
def gen(ctx, account):
    """Generate a PIN for the given account"""

    # Open the secrets file
    secrets_file = ctx.obj["secrets_file"]
    secrets_map = get_secrets(ctx, ctx.obj["secrets_file"])
    account = account.strip().lower()

    if not secrets_map:
        ctx.fail(f'No account listed in secrets file "{secrets_file}"')

    if account not in secrets_map:
        ctx.fail(f'No account named "{account}" in secrets file "{secrets_file}"')

    # Generate and print the PIN
    try:
        click.echo(pyotp.TOTP(secrets_map[account]).now())
    except TypeError:
        ctx.fail(f"The secret for account '{account}' is not a valid TOTP token")


@cli.command()
@click.argument("account")
@click.argument("secret")
@click.pass_context
def add(ctx, account, secret):
    """Add a new account"""
    # Open the secrets file
    secrets_file = ctx.obj["secrets_file"]
    data = get_toml_data(ctx, secrets_file)

    if account in data["account"]:
        click.fail(f'An account named "{account}" already exists.')

    if data["format_version"] == 1:
        data["account"][account] = {"secret": secret}
    else:
        data["account"][account] = {
            "secret": encrypt_ascii_text(ctx.obj["key"], secret)
        }

    with secrets_file.open("w", encoding="utf8") as f:
        toml.dump(data, f)

    # Generate and print the PIN
    click.echo("Account added")


@cli.command()
@click.argument("account")
@click.pass_context
def rm(ctx, account):
    """Remove an account"""

    # Open the secrets file
    secrets_file = ctx.obj["secrets_file"]
    data = get_toml_data(ctx, secrets_file)

    if account not in data["account"]:
        click.fail(f'No account named "{account}".')

    res = data["account"].pop(account)

    with secrets_file.open("w", encoding="utf8") as f:
        toml.dump(data, f)

    # Generate and print the PIN
    click.echo(f"Account removed: {account}={res['secret']}")


#   {"secret":"SECRE===","issuer":"App","label":"Name","digits":6,"type":"TOTP","algorithm":"SHA1","thumbnail":"Default","last_used":1685960904968,"used_frequency":0,"period":30,"tags":[]}]


class AndOTPExportFormat(TypedDict):
    secret: str
    label: str
    last_used: int
    tags: Tuple[str]
    used_frequency: int
    digits: int
    period: int
    algorithm: str
    thumbnail: str
    type: str
    issuer: str


@cli.command()
@click.option(
    "--format",
    help="App format to use. Only andotp is supported for now.",
    default="andotp",
)
@click.argument("path")
@click.pass_context
def export(ctx, path, format="andotp"):
    """Add a new account"""

    if format != "andotp":
        ctx.fail("Only andotp is supported for now.")

    secrets_map = get_secrets(ctx, ctx.obj["secrets_file"])
    export = []
    timestamp = int(dt.datetime.now().timestamp() * 1000)

    for name, secret in secrets_map.items():
        export.append(
            AndOTPExportFormat(
                secret=secret,
                label=name,
                last_used=timestamp,
                tags=(),
                used_frequency=0,
                digits=6,
                period=30,
                algorithm="SHA1",
                thumbnail="Default",
                type="TOTP",
                issuer="tetripin",
            )
        )

    with Path(path).open("w", encoding="utf8") as f:
        json.dump(export, f, indent=4)

    click.echo("Done")


def main():
    cli(auto_envvar_prefix="TETRIPIN")


if __name__ == "__main__":
    main()
