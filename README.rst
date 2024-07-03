Tetripin, a command line TOTP 2 factor auth manager
===================================================

Tetripin is a cli 2FA manager that can generate the one time PIN from your terminal. It's compatible with most TOTP services, e.g: the ones that use the regular settings for Google Authenticator such as most crypto-currency exchanges, lastpass and discord...

::

    $ tetripin unlock # choose a password
    $ tetripin add Bittrex JBSWY3DPEHPK3PXP # TOTP seed
    Account added
    $ tetripin gen Bittrex
    969804

Or:

::

    $ tetripin tui

    .. image:: screenshot.png
        :alt: Tetripin TUI example
        :align: center

Seeds are encrypted using your password, and the key is stored in your OS keyring, so it will be automatically unlocked on logging.

You can manually lock the codes with

::

    $ tetripin lock


If you don't lock your codes, they are easy to list if somebody has physical access to your machine:

::
    $ tetripin listsecrets

They can also be exported to the andotp android app format:

::

    $ tetripin export


You can find where the seeds are saved with (E.G: for backup):

::

    $ tetripin listconfig




Support
--------------

It works on Windows/Mac/Linux, but support only TOTP with default settings::

    period = 30
    digits = 6
    algorithm = SHA1

If you need other settings, open a github issue.

Installation
------------

You need to know how pip works. If you don't, vote on the github issue asking for binaries. Indicate your OS name and version.

```
pip install tetripin
```


Future?
-------

- restore
- read from qrcode local file or url
- deal with other algo settings
- add support for steam
- add sync service
- desktop GUI
- mobile GUI
- web GUI
