#!/usr/bin/env python
# coding: utf8

from __future__ import (
    unicode_literals,
    print_function,
    absolute_import,
    division
)


import os
import re
import sys
import warnings

warnings.filterwarnings('ignore', 'The virtualenv distutils package')

try:
    from path import Path
except ImportError:
    msg = 'Unable to import path.py. Please instal it. E.G: pip install path.py'
    sys.exit(msg)

try:
    from appdirs import user_data_dir
except ImportError:
    msg = 'Unable to import appdirs. Please instal it. E.G: pip install appdirs'
    sys.exit(msg)

try:
    import pyotp
except ImportError:
    sys.exit('Unable to import pyotp. Please instal it. E.G: pip install pyotp')

try:
    import toml
except ImportError:
    sys.exit('Unable to import toml. Please instal it. E.G: pip install toml')

try:
    import click
    click.disable_unicode_literals_warning = True
except ImportError:
    sys.exit('Unable to import click. Please instal it. E.G: pip install click')


# a Few defaults
DATA_DIR = user_data_dir("tetripin", "tetricoins", version="0.1")


def get_toml_data(ctx, secrets_file):
    try:
        with open(secrets_file) as f:
            data = toml.load(f)

    except (OSError, IOError) as e:
        msg = 'Unable to open the secrets file "{}": {}'
        ctx.fail(msg.format(secrets_file, e))

    # Handle bad TOML
    except toml.TomlDecodeError as e:
        msg = "'{}' is not a valid TOML file (Error given is: {})\n"
        error = e.args[0]
        if error == 'Invalid date or number':
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
                "twice. Check that you didn't use '{}' several times."
            ).format(duplicate)

        ctx.fail(msg.format(secrets_file, e))

    except UnicodeDecodeError:
        msg = 'Unable to open the secrets file "{}": it must be UTF8'
        ctx.fail(msg.format(secrets_file))

    # Handle missing sections
    try:
        version = data['format_version']
    except KeyError:
        msg = 'Version is missing from the secrets file "{}"'
        ctx.fail(msg.format(secrets_file))

    try:
        secrets = data['account']
    except KeyError:
        msg = '"account" section is missing from the secrets file "{}"'
        ctx.fail(msg.format(secrets_file))

    return data


def get_secrets(ctx, secrets_file):
    """ Parse TOML file and return secrets """
    secrets_map = {}
    data = get_toml_data(ctx, secrets_file)

    # Load values from the file and handle missing ones
    for label, infos in data['account'].items():
        label = label.lower().strip()
        if label:
            secret = infos.get('secret', '').strip()
            if not secret:
                msg = "Account '{}' don't have a secret."
                click.fail(msg)
            secrets_map[label] = secret

    return secrets_map


@click.group(name="tetripin")
@click.option(
    '--secrets-file',
    help='Path to the toml files containing the secrets.'
)
@click.option(
    '--data-dir',
    default=DATA_DIR,
    help='Path to settings directory. Set to an empty string to ignore it.',
)
@click.pass_context
def cli(ctx, secrets_file, data_dir):
    """ Code running for all commands """
    ctx.obj = {}

    # Try to get a setting dir
    if data_dir:
        data_dir = Path(data_dir)
        if not data_dir.isdir():
            click.echo("Setting dir does not exist. Attempting to create one.")
            try:
                data_dir.makedirs_p()
            except (OSError, IOError) as e:
                msg = 'Unable to create settings dir "{}": {}'
                msg = msg.format(data_dir, e)
                click.echo(click.style(msg, fg='red', err=True))
                data_dir = None

    # Try to get a secrets file
    if not secrets_file:

        if not data_dir:
            ctx.fail(
                "You need to provide a path to the secrets file. "
                "Either allow the one from the settings dir to be used, "
                "set TETRIPIN_SECRETS or pass --secrets-file"
            )

        secrets_file = data_dir / 'secrets.toml'
        try:
            # generate an empty file
            if not secrets_file.isfile():
                with secrets_file.open('a', encoding="utf8") as f:
                    toml.dump({'format_version': 1, "account": {}}, f)
            else: # update the access time
                with secrets_file.open('a', encoding="utf8") as f:
                    secrets_file.utime(None)
        except (OSError, IOError) as e:
            msg = 'Unable to open the secrets file "{}": {}'
            ctx.fail(msg.format(secrets_file, e))
        except UnicodeDecodeError:
            ctx.fail('Unable to open the secrets file "{}": it must be UTF8')

    ctx.obj['data_dir'] = data_dir
    ctx.obj['secrets_file'] = secrets_file


@cli.command()
@click.pass_context
def listconfig(ctx):
    """ Print informations about the program conf"""
    for pair in ctx.obj.items():
        click.echo('{}={}'.format(*pair))


@cli.command()
@click.pass_context
def listsecrets(ctx):
    """ Print all the accounts and their secrets"""
    secrets_map = get_secrets(ctx, ctx.obj['secrets_file'])
    for pair in secrets_map.items():
        click.echo('{}={}'.format(*pair))


@cli.command()
@click.argument('account')
@click.pass_context
def gen(ctx, account):
    """ Generate a PIN for the given account """

    # Open the secrets file
    secrets_file = ctx.obj['secrets_file']
    secrets_map = get_secrets(ctx, ctx.obj['secrets_file'])
    account = account.strip().lower()

    if not secrets_map:
        ctx.fail('No account listed in secrets file "{}"'.format(secrets_file))

    if account not in secrets_map:
        msg = 'No account named "{}" in secrets file "{}"'
        ctx.fail(msg.format(account, secrets_file))

    # Generate and print the PIN
    try:
        click.echo(pyotp.TOTP(secrets_map[account]).now())
    except TypeError:
        msg = "The secret for account '{}' is not a valid TOTP token"
        ctx.fail(msg.format(account))

@cli.command()
@click.argument('account')
@click.argument('secret')
@click.pass_context
def add(ctx, account, secret):
    """ Add a new account """

    # Open the secrets file
    secrets_file = ctx.obj['secrets_file']
    data = get_toml_data(ctx, secrets_file)

    if account in data['account']:
        click.fail('An account named "{}" already exists.')

    data['account'][account] = {'secret': secret}

    with secrets_file.open('w') as f:
        toml.dump(data, f)

    # Generate and print the PIN
    click.echo('Account added')

@cli.command()
@click.argument('account')
@click.pass_context
def rm(ctx, account):
    """ Remove an account """

    # Open the secrets file
    secrets_file = ctx.obj['secrets_file']
    data = get_toml_data(ctx, secrets_file)

    if account not in data['account']:
        click.fail('No account named "{}".')

    res = data['account'].pop(account)

    with secrets_file.open('w') as f:
        toml.dump(data, f)

    # Generate and print the PIN
    click.echo('Account removed: {}={}'.format(account, res['secret']))


def main():
    cli(auto_envvar_prefix='TETRIPIN')

if __name__ == '__main__':
    main()
