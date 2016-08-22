use v6c;

use Digest::HMAC;
use OpenSSL::Digest;
use Base64;

use PKCS5::PBKDF2;

#-------------------------------------------------------------------------------
unit package Auth;

#-------------------------------------------------------------------------------
class SCRAM {

  has Str $!username;
  has Str $!password;
  has Str $!authzid = '';
  has Bool $!strings-are-prepped = False;

  # Name of digest, usable values are sha1 and sha256
  has Callable $!PRF;

  # Client side and server side communication. Pick one or the other.
  has $!client-side;
  has $!server-side;

  # Normalization of username and password can be skipped if normal
  # ASCII is used
  has Bool $!skip-saslprep = False;

  # Set these values before creating the messages
  # Nonce size in bytes
  has Int $.c-nonce-size is rw = 24;
  has Str $.c-nonce is rw;
  has Str $.reserved-mext is rw;
  has Hash $.extensions is rw = %();

  # Strings used for communication
  has Str $!gs2-header;
  has Str $!client-first-message-bare;
  has Str $!client-first-message;

  has Str $!server-first-message;
  has Str $!s-nonce;
  has Str $!s-salt;
  has Str $!s-iter;

  #-----------------------------------------------------------------------------
  submethod BUILD (
    Str:D :$username!,
    Str:D :$password!,

    Callable :$PRF = &sha1,
    Str :$authzid,
    :$client-side,
    :$server-side,
  ) {

    $!username = $username;
    $!password = $password;
    $!authzid = $authzid;

    $!PRF = $PRF;

    # Check client or server object capabilities
    if $client-side.defined {
      die 'Only a client or server object must be chosen'
          if $server-side.defined;

      die 'message object misses some methods'
          unless ?$client-side.^can('message1')
          and ?$client-side.^can('message2')
#          and ?$client-side.^can('message3')
          and ?$client-side.^can('error')
          ;

      $!client-side = $client-side;
    }

    elsif $server-side.defined {
      die 'Client object misses some methods'
          unless ?$server-side.^can('message1')
          and ?$server-side.^can('message2')
#          and ?$server-side.^can('message3')
          and ?$client-side.^can('error')
          ;

      $!server-side = $server-side;
    }

    else {
      die 'At least a client or server object must be chosen';
    }
  }

  #-----------------------------------------------------------------------------
  method skip-saslprep ( Bool:D :$skip ) {

    $!skip-saslprep = $skip;
    $!strings-are-prepped = False unless $skip;
  }

  #-----------------------------------------------------------------------------
  method start-scram( ) {

    # Can only done from client so check client object
    die 'No client object defined' unless $!client-side.defined;

    # Prepare message and send to server. Returns server-first-message
    self!client-first-message;
    $!server-first-message = $!client-side.message1($!client-first-message);
say "server first message: ", $!server-first-message;

    my Str $error = self!process-server-first;
    if ?$error {
      $!client-side.error($error);
      return fail($error);
    }

    
  }

  #-----------------------------------------------------------------------------
  method !client-first-message ( ) {

    # check state of strings
    unless $!strings-are-prepped {

      $!username = self!saslPrep($!username);
#      $!password = self!saslPrep($!password);
      $!authzid = self!saslPrep($!authzid) if ?$!authzid;
      $!strings-are-prepped = True;
    }

    self!set-gs2header;
say "gs2 header: ", $!gs2-header;

    self!set-client-first;
say "client first message bare: ", $!client-first-message-bare;
say "client first message: ", $!client-first-message-bare;

  }

  #-----------------------------------------------------------------------------
  method !set-gs2header ( ) {

    my $aid = ($!authzid.defined and $!authzid.chars) ?? "a=$!authzid" !! '';
    $!gs2-header = "n,$aid";
  }

  #-----------------------------------------------------------------------------
  method !set-client-first ( ) {

    $!client-first-message-bare = 
      ( $!reserved-mext.defined and $!reserved-mext.chars )
        ?? "m=$!reserved-mext,"
        !! '';

    $!client-first-message-bare ~= "n=$!username,";

    unless ? $!c-nonce {
      $!c-nonce = encode-base64(
        Buf.new((for ^$!c-nonce-size { (rand * 256).Int }))
        , :str
      );
    }

    $!client-first-message-bare ~= "r=$!c-nonce";

    # Not needed anymore, neccesary to reset to prevent reuse by hackers
    # So when user needs its own nonce again, set it before starting scram.
    $!c-nonce = Str;

    # Only single character keynames are taken
    my Str $ext = (
      map -> $k, $v { next if $k.chars > 1; "$k=$v"; }, $!extensions.kv
    ).join(',');

    $!client-first-message-bare ~= ",$ext" if ?$ext;

    $!client-first-message = "$!gs2-header,$!client-first-message-bare";
  }

  #-----------------------------------------------------------------------------
  method !process-server-first ( --> Str ) {

    my Str $error = '';

    $error = 'Undefined first server message' unless ? $!server-first-message;
    return $error if $error;

    ( my $nonce, my $salt, my $iter) = $!server-first-message.split(',');

    $nonce ~~ s/^ 'r=' //;
    $error = 'no nonce found' if !? $nonce or !?$/; # Check s/// operation too
    return $error if $error;

    $salt ~~ s/^ 's=' //;
    $error = 'no salt found' if !? $salt or !?$/;
    return $error if $error;

    $iter ~~ s/^ 'i=' //;
    $error = 'no iteration count found' if !? $iter or !?$/;
    return $error if $error;

    $!s-nonce = $nonce;
    $!s-salt = $salt;
    $!s-iter = $iter;

    $error;
  }

  #-----------------------------------------------------------------------------
  method !saslPrep ( Str:D $text --> Str ) {

    my Str $prepped-text = $text;
    unless $!skip-saslprep {
      # prep string
    }

    # never skip this
    $prepped-text = self!encode-name($prepped-text);
  }

  #-----------------------------------------------------------------------------
  method !decode-name ( Str $name is copy --> Str ) {

    $name ~~ s:g/ '=2c' /,/;
    $name ~~ s:g/ '=3d' /=/;
  }

  #-----------------------------------------------------------------------------
  method !encode-name ( Str $name is copy --> Str ) {

    $name ~~ s:g/ '=' /=3d/;
    $name ~~ s:g/ ',' /=2c/;

    $name;
  }
}
