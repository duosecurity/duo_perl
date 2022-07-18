# Deprecation Notice

This repository is deprecated by Duo Security.  The repository will remain public and visible, and integrations built using this repository’s code will continue to work.  You can also continue to fork, clone, or pull from this repository.

However, Duo will not provide any further releases or enhancements.

Duo recommends migrating your application to the Duo Universal Prompt. Refer to [our documentation](https://duo.com/docs/universal-prompt-update-guide) for more information on how to update.

For frequently asked questions about the impact of this deprecation, please see the [Repository Deprecation FAQ](https://duosecurity.github.io/faq.html)

----

# Overview

[![Build Status](https://github.com/duosecurity/duo_perl/workflows/Perl%20CI/badge.svg)](https://github.com/duosecurity/duo_perl/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_perl)](https://github.com/duosecurity/duo_perl/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_perl)](https://github.com/duosecurity/duo_perl/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_perl)](https://github.com/duosecurity/duo_perl/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_perl/blob/master/LICENSE)

**duo_perl** - Duo two-factor authentication for Perl web applications

This package allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any web login form - without setting up secondary user accounts, directory synchronization, servers, or hardware.

What's here:

* `js` - Duo Javascript library, to be hosted by your webserver.
* `DuoWeb.pm` - Duo Perl SDK to be integrated with your web application
* `test.pl` -  Unit tests for our SDK

# Usage

Developer documentation: <http://www.duosecurity.com/docs/duoweb-v2>

# Testing

```
$ perl Makefile.PL
$ make test
```

# Support

Report any bugs, feature requests, etc. to us directly:
support@duosecurity.com

Have fun!

<http://www.duosecurity.com>
