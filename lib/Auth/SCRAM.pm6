use v6c;

#use Auth::SCRAM::Client;
#use Auth::SCRAM::Server;

use Digest::HMAC;
use OpenSSL::Digest;
#use Base64;
use PKCS5::PBKDF2;

#-------------------------------------------------------------------------------
unit package Auth;

#TODO Implement server side
#TODO Keep information when calculated. User requst boolean
#     and username/password/authzid must be kept the same. This saves time.

#-------------------------------------------------------------------------------
class SCRAM {

  has Bool $!role-imported = False;
  has PKCS5::PBKDF2 $!pbkdf2;
  has Callable $!CGH;

#`{{
  has Str $!username;
  has Str $!password;
  has Str $!authzid = '';
  has Bool $!strings-are-prepped = False;

  # Name of digest, usable values are sha1 and sha256

  # Client side and server side communication. Pick one or the other.
  has $!client-side;
  has $!server-side;

  # Set these values before creating the messages
  # Nonce size in bytes
  has Int $.c-nonce-size is rw = 24;
  has Str $.c-nonce is rw;
#TODO use of reserved mext and extensions
  has Str $.reserved-mext is rw;
  has Hash $.extensions is rw = %();

  # Strings used for communication
  has Str $!gs2-bind-flag;
  has Str $!gs2-header;
  has Str $!client-first-message-bare;
  has Str $!client-first-message;

  has Str $!server-first-message;
  has Int $.s-nonce-size is rw = 18;
  has Str $.s-nonce is rw;
  has Buf $!s-salt;
  has Int $!s-iter;

  has Buf $!salted-password;
  has Buf $!client-key;
  has Buf $!stored-key;

  has Str $!channel-binding;
  has Str $!client-final-without-proof;
  has Str $!client-final-message;
  has Str $!auth-message;
  has Buf $!client-signature;
  has Buf $!client-proof;

  has Str $!server-final-message;
  has Buf $!server-key;
  has Buf $!server-signature;
}}

#`{{ # Bug in perl6 multis with role
  #-----------------------------------------------------------------------------
  # Client side scram procedures
  multi submethod BUILD (
    Str:D :$username!,
    Str:D :$password!,
    Any:D :$client-side!,
    Str :$authzid,
    Callable :$CGH
  ) {

    $!CGH = $CGH // &sha1;
    $!pbkdf2 .= new(:$CGH);

    die 'message object misses some methods'
      unless self!test-methods(
        $client-side,
        <client-first client-final error>
      );

    if not $!role-imported {
      need Auth::SCRAM::Client;
      import Auth::SCRAM::Client;
      $!role-imported = True;
    }
    self does Auth::SCRAM::Client;
    self.init( :$username, :$password, :$authzid, :$client-side);
  }

  #-----------------------------------------------------------------------------
  # Server side scram procedures
  multi submethod BUILD (
    Str:D :$username!,
    Str:D :$password!,
    Any:D :$server-side!,
    Str :$authzid,
    Callable :$CGH = &sha1
  ) {

    $!CGH = $CGH;
    $!pbkdf2 .= new(:$CGH);

    die 'Server object misses some methods'
      unless self!test-methods(
        $server-side,
        <server-first server-final error>
      );

    if not $!role-imported {
      need Auth::SCRAM::Server;
      import Auth::SCRAM::Server;
      $!role-imported = True;
    }
    self does Auth::SCRAM::Server;
    self.init( :$username, :$password, :$authzid, :$server-side);
  }

  #-----------------------------------------------------------------------------
  # Server side scram procedures for basic credential parameter generation
  multi submethod BUILD (
    Callable :$CGH = &sha1,
    Any:D :$server-side!
  ) {

    $!CGH = $CGH;
    $!pbkdf2 .= new(:$CGH);

    if not $!role-imported {
      need Auth::SCRAM::Server;
      import Auth::SCRAM::Server;
      $!role-imported = True;
    }
    self does Auth::SCRAM::Server;
    self.init(:$server-side);
  }
}}

#`{{}}
  #-----------------------------------------------------------------------------
  submethod BUILD (
    Str :$username,
    Str :$password,
    Str :$authzid,

    Callable :$CGH = &sha1,
    :$client-side,
    :$server-side,
    Bool :$basic-use = False
  ) {

#    $!username = $username;
#    $!password = $password;
#    $!authzid = $authzid;

    $!CGH = $CGH;
    $!pbkdf2 .= new(:$CGH);

    # Check client or server object capabilities
    if $client-side.defined {
      die 'No username and/or password provided'
        unless ? $username and ? $password;

      die 'Only a client or server object must be chosen'
        if $server-side.defined;

      die 'message object misses some methods'
        unless self!test-methods(
          $client-side,
          <client-first client-final error>
        );

      if not $!role-imported {
        need Auth::SCRAM::Client;
        import Auth::SCRAM::Client;
        $!role-imported = True;
      }
      self does Auth::SCRAM::Client;
      self.init( :$username, :$password, :$authzid, :$client-side);
    }


    elsif $server-side.defined {
#      if $basic-use {

        if not $!role-imported {
          need Auth::SCRAM::Server;
          import Auth::SCRAM::Server;
          $!role-imported = True;
        }
        self does Auth::SCRAM::Server;
        self.init(:$server-side);
#      }

#`{{
      else {

        die 'Server object misses some methods'
          unless self!test-methods(
            $server-side,
            <server-first server-final error>
          );

        if not $!role-imported {
          need Auth::SCRAM::Server;
          import Auth::SCRAM::Server;
          $!role-imported = True;
        }
        self does Auth::SCRAM::Server;
        self.init( :$username, :$password, :$authzid, :$server-side);
      }
}}
    }


    else {
      die 'At least a client or server object must be chosen';
    }
  }



#`{{
  #-----------------------------------------------------------------------------
  method start-scram( Str :$client-first-message --> Str ) {

    my Str $error = '';

    if $!client-side.defined {
      $error = self!client-side-process;
    }

    else {
say "Server side processing";

      if ? $client-first-message {
        $!client-first-message = $client-first-message;
        $error = self!server-side-process;
      }

      else {
        $error = 'No client first message provided';
      }
    }

    $error;
  }

  #-----------------------------------------------------------------------------
  method !client-side-process ( ) {

    # Can only done from client so check client object
    die 'No client object defined' unless $!client-side.defined;

    # Prepare message and send to server. Returns server-first-message
    self!client-first-message;
    $!server-first-message = $!client-side.client-first($!client-first-message);
#say "server first message: ", $!server-first-message;

    my Str $error = self!process-server-first;
    if ?$error {
      $!client-side.error($error);
      return $error;
    }

    # Prepare for second round ... `doiinggg' :-P
    self!client-final-message;
    $!server-final-message = $!client-side.client-final($!client-final-message);
#say "server final message: ", $!server-final-message;
    $error = self!verify-server;
    if ?$error {
      $!client-side.error($error);
      return $error;
    }

    $!client-side.cleanup if $!client-side.^can('cleanup');
    '';
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
#say "gs2 header: ", $!gs2-header;

    self!set-client-first;
#say "client first message bare: ", $!client-first-message-bare;
#say "client first message: ", $!client-first-message-bare;

  }

  #-----------------------------------------------------------------------------
  method !set-gs2header ( ) {

    my $aid = ($!authzid.defined and $!authzid.chars) ?? "a=$!authzid" !! '';

    $!gs2-bind-flag = 'n';
    $!gs2-header = "$!gs2-bind-flag,$aid";
  }

  #-----------------------------------------------------------------------------
  method !set-client-first ( ) {

    $!client-first-message-bare = 
      ( $!reserved-mext.defined and $!reserved-mext.chars )
        ?? "m=$!reserved-mext,"
        !! '';

    $!client-first-message-bare ~= "n=$!username,";

    $!c-nonce = encode-base64(
      Buf.new((for ^$!c-nonce-size { (rand * 256).Int })),
      :str
    ) unless ? $!c-nonce;

    $!client-first-message-bare ~= "r=$!c-nonce";

# Not needed anymore, necessary to reset to prevent reuse by hackers
# So when user needs its own nonce again, set it before starting scram.
$!c-nonce = Str;
#TODO used later to check returned server nonce, so not yet resetting it here!

    # Only single character keynames are taken
    my Str $ext = (
      map -> $k, $v { next if $k.chars > 1; "$k=$v"; }, $!extensions.kv
    ).join(',');

    $!client-first-message-bare ~= ",$ext" if ?$ext;

    $!client-first-message = "$!gs2-header,$!client-first-message-bare";
  }

  #-----------------------------------------------------------------------------
  method !client-final-message ( ) {

    # Using named arguments, the clients object doesn't need to
    # support all variables as long as a Buf is returned
    my Buf $mangled-password;
    if $!client-side.^can('mangle-password') {
      $mangled-password = $!client-side.mangle-password(
        :$!username, :$!password, :$!authzid
      );
    }

    else {
      $mangled-password = self.mangle-password($password);
    }

    $!salted-password = $!pbkdf2.derive( $mangled-password, $!s-salt, $!s-iter);

    $!client-key = hmac( $!salted-password, 'Client Key', &$!CGH);
    $!stored-key = $!CGH($!client-key);

    # biws is from encode-base64( 'n,,', :str)
#TODO gs2-header [ cbind-data ]
    $!channel-binding = "c=biws";
    $!client-final-without-proof = "$!channel-binding,r=$!s-nonce";

    $!auth-message = 
      ( $!client-first-message-bare,
        $!server-first-message,
        $!client-final-without-proof
      ).join(',');

    $!client-signature = hmac( $!stored-key, $!auth-message, &$!CGH);

    $!client-proof .= new;
    for ^($!client-key.elems) -> $i {
      $!client-proof[$i] = $!client-key[$i] +^ $!client-signature[$i];
    }

    $!client-final-message =
      [~] $!client-final-without-proof,
          ',p=',
          encode-base64( $!client-proof, :str);
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
#TODO Check if it starts with client nonce

    $salt ~~ s/^ 's=' //;
    $error = 'no salt found' if !? $salt or !?$/;
    return $error if $error;

    $iter ~~ s/^ 'i=' //;
    $error = 'no iteration count found' if !? $iter or !?$/;
    return $error if $error;

    $!s-nonce = $nonce;
    $!s-salt = decode-base64( $salt, :bin);
    $!s-iter = $iter.Int;

    $error;
  }

  #-----------------------------------------------------------------------------
  method !verify-server ( --> Str ) {

    my Str $error = '';

    if $!server-final-message ~~ m/^ 'e=' / {
      # error
    }

    elsif $!server-final-message ~~ m/^ 'v=' / {
      # verify server
      my Str $sv = $!server-final-message;
      $sv ~~ s/^ 'v=' //;

      $!server-key = hmac( $!salted-password, 'Server Key', &$!CGH);
      $!server-signature = hmac( $!server-key, $!auth-message, &$!CGH);

      if encode-base64( $!server-signature, :str) ne $sv {
        $error = 'Server verification failed';
      }
    }

    else {
      $error = 'Server response not recognized';
    }

    $error;
  }

  #-----------------------------------------------------------------------------
  method !server-side-process ( --> Str ) {

    my Str $error = self!process-client-first;
    if ?$error {
      $!client-side.error($error);
      return $error;
    }

    self!server-first-message;

    $error = self!process-client-final;
    if ?$error {
      $!client-side.error($error);
      return $error;
    }

    '';
  }

  #-----------------------------------------------------------------------------
  method !process-client-first ( --> Str ) {

    my Str $error = '';

    # First get the gs2 header
    for $!client-first-message.split( ',', 3) {

      when /^ <[ny]> $/ {
        $!gs2-bind-flag = $_;
      }

      when /^ 'p=' / {
        $!gs2-bind-flag = $_;
        $!gs2-bind-flag ~~ s/^ 'p=' //;
      }

      when /^ 'a=' / {
        $!authzid = $_;
        $!authzid ~~ s/^ 'a=' //;
      }

      when /^ $/ {
        # no authzid
      }

      default {

        for .split(',') {
          when /^ 'n=' / {
            $!username = $_;
            $!username ~~ s/^ 'n=' //;
#            $!username = self!decode-name($_);
          }

          when /^ 'r=' / {
            $!c-nonce = $_;
            $!c-nonce ~~ s/^ 'r=' //;
          }

          when /^ 'm=' / {
            $!reserved-mext = $_;
            $!reserved-mext ~~ s/^ 'm=' //;
          }

          when /^ 'p=' / {
            $!gs2-bind-flag = $_;
            $!gs2-bind-flag ~~ s/^ 'p=' //;
          }

          default {
#TODO gather extensions
          }
        }
      }
    }

    if ? $!username and ? $!authzid and $!server-side.^can('authzid') {
      if not $!server-side.authzid( $!username, $!authzid) {
        return "User '$!username' may not use rights of '$!authzid'";
      }
    }

say "PC 1: $!username, $!c-nonce";

    $error;
  }

  #-----------------------------------------------------------------------------
  # server-first-message =
  #                   [reserved-mext ","] nonce "," salt ","
  #                   iteration-count ["," extensions]
  method !server-first-message ( ) {

    $!s-nonce = encode-base64(
      Buf.new((for ^$!s-nonce-size { (rand * 256).Int })),
      :str
    ) unless ? $!s-nonce;

    if $!server-side.^can('salt') {
      $!s-salt = $!server-side.salt;
    }

    else {
      $!s-salt = Buf.new((for ^$!s-nonce-size { (rand * 256).Int }));
    }

    if $!server-side.^can('iterations') {
      $!s-iter = $!server-side.iterations;
    }

    else {
      $!s-iter = 4096;
    }

    my $s1stm = ? $!reserved-mext ?? "m=$!reserved-mext," !! '';
    $s1stm ~= "r=$!c-nonce$!s-nonce"
              ~ ",s=" ~ encode-base64( $!s-salt, :str)
              ~ ",i=$!s-iter";
    $s1stm ~= $!extensions.elems
              ?? ',' ~ ( map -> $k, $v { next if $k.chars > 1; "$k=$v"; },
                   $!extensions.kv
                 ).join(',')
              !! '';

    $!server-first-message = $s1stm;
    $!client-final-message = $!server-side.server-first($!server-first-message);
  }

  #-----------------------------------------------------------------------------
  method !process-client-final ( --> Str ) {

    my Str $error = '';

    for $!client-final-message.split(',') {
      when /^ 'c=' / {
        $!channel-binding = $_;
        $!channel-binding ~~ s/^ 'c=' //;
      }

      when /^ 'r=' / {
        my Str $nonce = $_;
        $nonce ~~ s/^ 'r=' //;
        $error = 'not a proper nonce' unless $nonce eq $!c-nonce ~ $!s-nonce;
        return $error if ? $error;
      }

      when /^ 'p=' / {

#.........
        my Buf $mangled-password;
        if $!client-side.^can('mangle-password') {
          $mangled-password = $!client-side.mangle-password(
            :$!username, :$!password, :$!authzid
          );
        }

        else {
          $mangled-password = self.mangle-password($password);
        }

        $!salted-password = $!pbkdf2.derive( $mangled-password, $!s-salt, $!s-iter);

        $!client-key = hmac( $!salted-password, 'Client Key', &$!CGH);
        $!stored-key = $!CGH($!client-key);

        # biws is from encode-base64( 'n,,', :str)
    #TODO gs2-header [ cbind-data ]
        $!channel-binding = "c=biws";
        $!client-final-without-proof = "$!channel-binding,r=$!s-nonce";

        $!auth-message = 
          ( $!client-first-message-bare,
            $!server-first-message,
            $!client-final-without-proof
          ).join(',');

        $!client-signature = hmac( $!stored-key, $!auth-message, &$!CGH);

        $!client-proof .= new;
        for ^($!client-key.elems) -> $i {
          $!client-proof[$i] = $!client-key[$i] +^ $!client-signature[$i];
        }
      }

      default {
#TODO extensions processing
      }
    }

    '';
  }
}}

  #-----------------------------------------------------------------------------
  method derive-key (
    Str :$username, Str:D :$password, Str :$authzid,
    Buf:D :$salt, Int:D :$iter,
    Any:D :$helper-object
    --> Buf
  ) {

    # Using named arguments, the clients object doesn't need to
    # support all variables as long as a Buf is returned
    my Buf $mangled-password;
    if $helper-object.^can('mangle-password') {
      $mangled-password = $helper-object.mangle-password(
        :$username, :$password, :$authzid
      );
    }

    else {
      $mangled-password = Buf.new($password.encode);
    }

    $!pbkdf2.derive( $mangled-password, $salt, $iter);
  }

  #-----------------------------------------------------------------------------
  method client-key ( Buf $salted-password --> Buf ) {

    hmac( $salted-password, 'Client Key', &$!CGH);
  }

  #-----------------------------------------------------------------------------
  method stored-key ( Buf $client-key --> Buf ) {

    $!CGH($client-key);
  }

  #-----------------------------------------------------------------------------
  method client-signature ( Buf $stored-key, Str $auth-message --> Buf ) {

    hmac( $stored-key, $auth-message, &$!CGH);
  }

  #-----------------------------------------------------------------------------
  method server-key ( Buf $salted-password --> Buf ) {

    hmac( $salted-password, 'Server Key', &$!CGH);
  }

  #-----------------------------------------------------------------------------
  method server-signature ( Buf $server-key, Str $auth-message --> Buf ) {

    hmac( $server-key, $auth-message, &$!CGH);
  }

  #-----------------------------------------------------------------------------
  method saslPrep ( Str:D $text --> Str ) {

    my Str $prepped-text = $text;

#TODO prep string

    # Some character protection changes
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

  #-----------------------------------------------------------------------------
  method !test-methods ( $obj, @methods --> Bool ) {

    my Bool $all-there = True;
    for @methods -> $method {
      if !? $obj.^can($method) {
        $all-there = False;
        last;
      }
    }

    $all-there;
  }
}
