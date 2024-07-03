import base64
import getpass
import secrets
import shutil
from typing import Tuple, TypedDict

import keyring
import pyotp
import json

import datetime as dt
from path import Path

import toml
import click

from cryptography.fernet import InvalidToken
from tetripin.exceptions import TetripinError
from tetripin.tui import TOTPApp
from tetripin.utils import (
    EncryptionKey,
    get_key_from_keyring,
    ensure_secrets_file,
    load_secrets_from_toml,
    build_secret_map_from_toml,
    prompt_password,
    get_key_from_keyring,
    DATA_DIR,
)


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

    secrets_file = ensure_secrets_file(data_dir, secrets_file)
    ctx.obj = {}

    # if we use the old clear text format, attempt to convert it to the encrypted format
    try:
        data = load_secrets_from_toml(secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

    key = get_key_from_keyring()
    if ctx.invoked_subcommand != "upgrade-config":
        if data["format_version"] != 3:
            ctx.fail(
                "You have an old unsecured config file. Run 'tetripin upgrade-config' to secure it."
            )

        if not key and ctx.invoked_subcommand != "unlock":
            ctx.fail("You codes are locked. Use 'tetripin unlock' first.")

    ctx.obj["key"] = key
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
    try:
        secrets_map = build_secret_map_from_toml(
            ctx.obj["key"], ctx.obj["secrets_file"]
        )
    except TetripinError as e:
        ctx.fail(str(e))
    for name, value in secrets_map.items():
        click.echo(f"{name}={value}")


@cli.command()
@click.argument("account")
@click.pass_context
def gen(ctx, account):
    """Generate a PIN for the given account"""

    # Open the secrets file
    secrets_file = ctx.obj["secrets_file"]

    try:
        secrets_map = build_secret_map_from_toml(ctx.obj["key"], secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

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
    secrets_file = ctx.obj["secrets_file"]
    try:
        data = load_secrets_from_toml(secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

    if account in data["account"]:
        click.fail(f'An account named "{account}" already exists.')

    if data["format_version"] == 1:
        data["account"][account] = {"secret": secret}
    else:
        data["account"][account] = {"secret": ctx.obj["key"].encrypt_to_text(secret)}

    with secrets_file.open("w", encoding="utf8") as f:
        toml.dump(data, f)

    click.echo("Account added")


@cli.command()
@click.argument("account")
@click.pass_context
def rm(ctx, account):
    """Remove an account"""

    secrets_file = ctx.obj["secrets_file"]
    try:
        data = load_secrets_from_toml(secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

    if account not in data["account"]:
        click.fail(f'No account named "{account}".')

    res = data["account"].pop(account)

    with secrets_file.open("w", encoding="utf8") as f:
        toml.dump(data, f)

    click.echo(f"Account removed: {account}={res['secret']}")


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

    try:
        secrets_map = load_secrets_from_toml(ctx.obj["secrets_file"])
    except TetripinError as e:
        ctx.fail(str(e))

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


@cli.command()
@click.pass_context
def tui(ctx):
    app = TOTPApp(ctx.obj["key"], ctx.obj["secrets_file"])
    app.app.run()


@cli.command()
@click.pass_context
def upgrade_config(ctx):
    """Upgrade the format of the config file"""
    secrets_file = ensure_secrets_file(ctx.obj["data_dir"], ctx.obj["secrets_file"])

    try:
        old_data = load_secrets_from_toml(secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

    if old_data["format_version"] == 3:
        click.echo("You are already at the last version, nothing to do")

    click.echo(
        "This is going to convert your old config file to the new encrypted format."
    )

    backup_file = f'{ctx.obj["secrets_file"]}.bak'
    shutil.copyfile(ctx.obj["secrets_file"], backup_file)
    click.echo(f"A backup has been created: {backup_file}")

    old_key = get_key_from_keyring()
    salt = base64.b64encode(secrets.token_bytes(16)).decode("utf-8")
    data = {
        "format_version": 3,
        "account": {},
        "salt": salt,
    }
    try:
        secrets_map = build_secret_map_from_toml(old_key, secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

    password = prompt_password("Please chose a password to protect your codes.")
    new_key = EncryptionKey.from_password(password, salt)
    keyring.set_password("tetripin", "key", str(new_key))

    for account, secret in secrets_map.items():
        data["account"][account] = {"secret": new_key.encrypt_to_text(secret)}

    with secrets_file.open("w", encoding="utf8") as f:
        toml.dump(data, f)

    keyring.set_password("tetripin", "key", str(new_key))

    click.echo("Your secrets are now secured with your password.")
    click.echo(
        f"Check that everything works, then delete the backup file: {backup_file}"
    )


@cli.command()
@click.pass_context
def unlock(ctx):
    """Save the password to decrypt the codes in the OS keyring"""
    secrets_file = ensure_secrets_file(ctx.obj["data_dir"], ctx.obj["secrets_file"])

    try:
        data = load_secrets_from_toml(secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

    password = getpass.getpass("Enter your password: ")
    key = EncryptionKey.from_password(password, data["salt"])

    try:
        build_secret_map_from_toml(key, secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))
    except InvalidToken:
        ctx.fail("This password is incorrect")

    keyring.set_password("tetripin", "key", str(key))
    click.echo("Your codes are now unlocked.")


@cli.command()
@click.pass_context
def lock(ctx):
    """Remove the password from the OS keyring"""

    if click.confirm(
        "Lock the codes? Make sure you have access to the password. They cannot be recovered with it.",
        abort=True,
    ):
        keyring.delete_password("tetripin", "key")
        click.echo("Locking successful")
    else:
        # Handle the case where the user does not confirm
        click.echo("Locking aborded.")


def main():
    cli(auto_envvar_prefix="TETRIPIN")


if __name__ == "__main__":
    main()
