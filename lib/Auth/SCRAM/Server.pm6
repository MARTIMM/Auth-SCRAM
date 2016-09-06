use v6c;

use Base64;

#-------------------------------------------------------------------------------
unit package Auth;

#TODO Implement server side
#TODO Keep information when calculated. User requst boolean
#     and username/password/authzid must be kept the same. This saves time.

#-------------------------------------------------------------------------------
role SCRAM::Server {

  has Str $!username;
  has Str $!password;
  has Str $!authzid = '';
  has Bool $!strings-are-prepped = False;

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

  #-----------------------------------------------------------------------------
  method init ( :$server-side! ) {

    $!server-side = $server-side;

    die 'message object misses some methods'
      unless self.test-methods(
        $server-side,
        < credentials server-first server-final error >
      );
  }

  #-----------------------------------------------------------------------------
  method generate-user-credentials (
    Str :$username, Str :$password,
    Buf :$salt, Int :$iter,
    Any :$helper-object

    --> Hash
  ) {

    my Buf $salted-password = self.derive-key(
      :$username, :$password,
      :$salt, :$iter,
      :$helper-object,
    );

    my Buf $client-key = self.client-key($salted-password);
    my Buf $stored-key = self.stored-key($client-key);
    my Buf $server-key = self.server-key($salted-password);

    %( iter => $iter,
       salt => encode-base64( $salt, :str),
       stored-key => encode-base64( $stored-key, :str),
       server-key => encode-base64( $server-key, :str)
    );
  }

  #-----------------------------------------------------------------------------
  method start-scram( Str:D $client-first-message! --> Str ) {

    $!client-first-message = $client-first-message;
    my Str $error = self!process-client-first;
    if ?$error {
      $!server-side.error($error);
      return $error;
    }

    $error = self!server-first-message;
    if ?$error {
      $!server-side.error($error);
      return $error;
    }

    $!client-final-message = $!server-side.server-first($!server-first-message);

    $error = self!process-client-final;
    if ?$error {
      $!server-side.error($error);
      return $error;
    }

    $error = $!server-side.server-final(
      'v=' ~ encode-base64( $!server-signature, :str)
    );
    if ?$error {
      $!server-side.error($error);
      return $error;
    }

    $!server-side.cleanup if $!server-side.^can('cleanup');

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

        $!client-first-message-bare = $_;

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

    $error;
  }

  #-----------------------------------------------------------------------------
  # server-first-message =
  #                   [reserved-mext ","] nonce "," salt ","
  #                   iteration-count ["," extensions]
  method !server-first-message ( ) {

    my Str $error = '';

    my Hash $credentials = $!server-side.credentials(
      $!username, $!authzid
    );
    return 'authentication failure' unless $credentials.elems;

    $!s-salt = Buf.new(decode-base64($credentials<salt>));
    $!s-iter = $credentials<iter>;

    $!s-nonce = encode-base64(
      Buf.new((for ^$!s-nonce-size { (rand * 256).Int })),
      :str
    ) unless ? $!s-nonce;

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

    '';
  }

  #-----------------------------------------------------------------------------
  method !process-client-final ( --> Str ) {

    for $!client-final-message.split(',') {
      when /^ 'c=' / {
        $!channel-binding = $_;
        $!channel-binding ~~ s/^ 'c=' //;
      }

      when /^ 'r=' / {
        my Str $nonce = $_;
        $nonce ~~ s/^ 'r=' //;
        return 'not a proper nonce' if $nonce ne $!c-nonce ~ $!s-nonce;
      }

      when /^ 'p=' / {

        my Str $proof = $_;
        my $client-final-without-proof = $!client-final-message;
        $client-final-without-proof ~~ s/ ',' $proof $//;

        $!auth-message = [~] $!client-first-message-bare,
                             ',', $!server-first-message,
                             ',', $client-final-without-proof;

        $proof ~~ s/^ 'p=' //;
        $!client-proof = Buf.new(decode-base64($proof));

#say "AML $!auth-message";

        my Hash $credentials = $!server-side.credentials(
          $!username, $!authzid
        );
        return 'authentication failure' unless $credentials.elems;

        $!stored-key = Buf.new(decode-base64($credentials<stored-key>));
        $!client-signature = self.client-signature( $!stored-key, $!auth-message);
        $!client-key = self.XOR( $!client-proof, $!client-signature);

        my Str $st-key = encode-base64( self.stored-key($!client-key), :str);
#say "Stored-keys: $st-key, $credentials<stored-key>";
        return 'authentication error' if $st-key ne $credentials<stored-key>;

        $!server-key = Buf.new(decode-base64($credentials<server-key>));
        $!server-signature = self.server-signature( $!server-key, $!auth-message);
      }

      default {
#TODO extensions processing
      }
    }

    '';
  }
}
