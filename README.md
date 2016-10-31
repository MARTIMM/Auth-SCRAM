# Salted Challenge Response Authentication Mechanism (SCRAM)

[![Build Status](https://travis-ci.org/MARTIMM/Auth-SCRAM.svg?branch=master)](https://travis-ci.org/MARTIMM/Auth-SCRAM)
[![License](http://martimm.github.io/label/License-label.svg)](http://www.perlfoundation.org/artistic_license_2_0)

This package implements secure authentication mechanism.

## Synopsis

```
# Example from rfc (C = client, s = server)
# C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
# S: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
# C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,
#    p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
# S: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=
#
class MyClient {

  # Send client first message to server and return server response
  method client-first ( Str:D $client-first-message --> Str ) {

    # Send $client-first-message to server;

    # Get server response, this is the server first message
    'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096';
  }

  # Send client final message to server and return server response
  method client-final ( Str:D $client-final-message --> Str ) {

    # Send $client-final-message to server.

    # Server response is server final message
    'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=';
  }

  method error ( Str:D $message --> Str ) {
    # Errors? nah ... (Famous last words!)
  }
}

my Auth::SCRAM $sc .= new(
  :username<user>,
  :password<pencil>,
  :client-side(MyClient.new),
);

$sc.c-nonce-size = 24;
$sc.c-nonce = 'fyko+d2lbbFgONRv9qkxdawL';

my $error = $sc.start-scram;
```

## DOCUMENTATION

See pod documentation in lib/SCRAM.pod6, lib/SCRAM/Client.pod6 and lib/SCRAM/Server.pod6

## INSTALLING THE MODULES

Use panda to install the package like so.
```
$ panda install Auth-SCRAM
```

## Versions of PERL, MOARVM

This project is tested with latest Rakudo built on MoarVM implementing Perl v6.c.

## BUGS, KNOWN LIMITATIONS

## TODO

* Keep information when calculated. User request boolean and username/password/authzid tuple must be kept the same. This saves time.
* Channel binding and several other checks

## CHANGELOG

For changes look for the file doc/CHANGES.md in this repository.

## AUTHORS

```
Marcel Timmerman (MARTIMM on github)
```
## CONTACT

MARTIMM on github: PKCS5
