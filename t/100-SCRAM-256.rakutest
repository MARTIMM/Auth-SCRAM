use v6.d;
use Test;

use OpenSSL::Digest;
use Auth::SCRAM;

#-------------------------------------------------------------------------------
# https://tools.ietf.org/html/rfc7677
#
# Example from rfc
# C: n,,n=user,r=rOprNGfwEbeRWgbNEkqO
# S: r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,
#    s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096
# C: c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,
#    p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
# S: v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=

class MyClient {

  #-----------------------------------------------------------------------------
  # send client first message to server and return server response
  method client-first ( Str:D $client-first-message --> Str ) {

    is $client-first-message,
       'n,,n=user,r=rOprNGfwEbeRWgbNEkqO',
       $client-first-message;

    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096';
  }

  #-----------------------------------------------------------------------------
  method client-final ( Str:D $client-final-message --> Str ) {

    is $client-final-message,
       < c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0
         p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
       >.join(','),
       $client-final-message;

    'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=';
  }

  # method mangle-password() is optional
  # method cleanup() is optional

  #-----------------------------------------------------------------------------
  method error ( Str:D $error-message --> Str ) {

  }
}

#-------------------------------------------------------------------------------
subtest {

  my Auth::SCRAM $sc .= new(
    :username<user>, :password<pencil>,
    :client-object(MyClient.new), :CGH(&sha256)
  );
  isa-ok $sc, Auth::SCRAM;

  $sc.c-nonce = 'rOprNGfwEbeRWgbNEkqO';

  is '', $sc.start-scram, 'client side authentication of user ok';

}, 'SCRAM tests';

#-------------------------------------------------------------------------------
done-testing;
