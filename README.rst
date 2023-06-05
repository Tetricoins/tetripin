Tetripin, a command line TOTP 2 factor auth manager
===================================================

If you have a lot of account with two factor authentification activated, using a separated device can take a lot of time.

Tetripin is a cli 2FA manager that can generate the one time PIN from your terminal. It's compatible with most TOTP services, e.g: the ones that use the regular settings for Google Authenticator such as most crypto-currency exchanges, lastpass and discord...

::

    $ tetripin add Bittrex JBSWY3DPEHPK3PXP
    Account added
    $ tetripin gen Bittrex
    969804


Support
--------------

It works on Windows/Mac/Linux, but support only TOTP with default settings::

    period = 30
    digits = 6
    algorithm = SHA1

If you need other settings, open a github issue.

It's written in Python 3.8+.

Installation
------------

You need to know how pip works. If you don't, vote on the github issue asking for binaries. Indicate your OS name and version.

```
python -m pip install tetripin
```

Binary may come in the future so you don't have to understand how pip works.

Future
-------

- backup
- restore
- rename
- import
- read from qrcode local file or url
- deal with other algo settings
- add support for steam
- add sync service
- desktop GUI
- mobile GUI
- web GUI
- keepass integration
- output time remaining

Tips
------------

If you can't find the `tetripin` command, you can still call tetripin doing::


    python -m tetripin


Export secrets::


    $ tetripin listsecrets # Export secrets
    bittrex=JBSWY3DPEHPK3PXP


Get conf infos::


    $ tetripin listconfig # List config values
    secrets_file=/home/user/.local/share/tetripin/0.1/secrets.toml
    data_dir=/home/user/.local/share/tetripin/0.1


WARNING
----------

If your secrets get stolen, people will be able to generate the PIN. Keep the secrets.toml safe !
