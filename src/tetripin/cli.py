from typing import Tuple, TypedDict
import pyotp
import json

import datetime as dt
from path import Path

import toml
import click


from tetripin.exceptions import TetripinError
from tetripin.tui import TOTPApp
from tetripin.utils import (
    ensure_key,
    ensure_secrets_file,
    load_secrets_from_toml,
    build_secret_map_from_toml,
    encrypt_ascii_text,
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

    key = ensure_key()
    secrets_file = ensure_secrets_file(data_dir, secrets_file)
    ctx.obj = {"key": key}

    # if we use the old clear text format, attempt to convert it to the encrypted format
    try:
        data = load_secrets_from_toml(secrets_file)
    except TetripinError as e:
        ctx.fail(str(e))

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
            try:
                secrets_map = build_secret_map_from_toml(ctx.obj["key"], secrets_file)
            except TetripinError as e:
                ctx.fail(str(e))

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
        data["account"][account] = {
            "secret": encrypt_ascii_text(ctx.obj["key"], secret)
        }

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


def main():
    cli(auto_envvar_prefix="TETRIPIN")


if __name__ == "__main__":
    main()
