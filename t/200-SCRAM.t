#!/usr/bin/env perl6

use v6.c;
use Test;

use Auth::SCRAM;
#use OpenSSL::Digest;
use Base64;

#-------------------------------------------------------------------------------
# Example from rfc
# C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
# S: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
# C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,
#    p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
# S: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=
#
#-------------------------------------------------------------------------------
# A user credentials database used to store added users to the system
# Credentials must be read from somewhere and saved to the same somewhere.
class Credentials {
  has Hash $!credentials-db;
  has Auth::SCRAM $!scram handles <start-scram s-nonce-size s-nonce>;

  #-----------------------------------------------------------------------------
  submethod BUILD ( ) {

#    $!scram .= new( :server-side(self), :basic-use);
    $!scram .= new(:server-side(self));
    isa-ok $!scram, Auth::SCRAM;
  }

  #-----------------------------------------------------------------------------
  method add-user ( $username, $password ) {

    my Buf $salt = self.salt;
    my Int $iter = self.iterations;

    my Buf $salted-password = $!scram.derive-key(
      :$username, :$password,
      :salt($salt), :iter($iter),
      :helper-object(self),
    );

    my Buf $client-key = $!scram.client-key($salted-password);
    my Buf $stored-key = $!scram.stored-key($client-key);
    my Buf $server-key = $!scram.server-key($salted-password);

    $!credentials-db{$username} = %(
      iter => $iter,
      salt => encode-base64( $salt, :str),
      stored-key => encode-base64( $stored-key, :str),
      server-key => encode-base64( $server-key, :str)
    );
say $!credentials-db.perl;
  }

  #-----------------------------------------------------------------------------
  method credentials ( Str $username, Str $authzid --> Hash ) {

#TODO what to do with authzid
    return $!credentials-db{$username};
  }

  #-----------------------------------------------------------------------------
  # method salt() is optional
  method salt ( --> Buf ) {

    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118);
  }

  #-----------------------------------------------------------------------------
  # method nonce() is optional
  method nonce ( --> Buf ) {

    Buf.new( 222, 183, 220, 52, 118, 9, 99, 86, 85, 189, 101, 108, 238);
  }

  #-----------------------------------------------------------------------------
  # method iterations() is optional
  method iterations ( --> Int ) {

    4096;
  }

  # method mangle-password() is optional

  #-----------------------------------------------------------------------------
  # return server first message to client, then receive and
  # return client final response
  method server-first ( Str:D $server-first-message --> Str ) {

    is $server-first-message,
       'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096',
       $server-first-message;

    < c=biws
      r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j
      p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
    >.join(',');
  }

  #-----------------------------------------------------------------------------
  # return server final message
  method server-final ( Str:D $server-final-message --> Str ) {

  }

  #-----------------------------------------------------------------------------
  method error ( Str:D $message --> Str ) {

  }

  #-----------------------------------------------------------------------------
  # method cleanup() is optional
  method cleanup ( ) {

    diag 'been here, done that';
  }
}

#-------------------------------------------------------------------------------
subtest {

  # Server actions in advance ...
  # - set up shop
  my Credentials $crd .= new;

  # - set up socket
  # - listen to socket and wait
  # - input from client
  # - fork process, parent returns to listening on socket
  # - child processes input as commands

  # - command is add a user
  $crd.add-user( 'user', 'pencil');
  $crd.add-user( 'gebruiker', 'potlood');
  $crd.add-user( 'utilisateur', 'crayon');

  # - command autenticate as 'user'/'pencil'
  my Str $client-first-message = 'n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL';
  $crd.s-nonce = '3rfcNHYJY1ZVvWVs7j';
  $crd.start-scram($client-first-message);

}, 'SCRAM tests';

#-------------------------------------------------------------------------------
done-testing;
