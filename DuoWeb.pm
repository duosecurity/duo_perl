package DuoWeb;

use strict;
use warnings;

use MIME::Base64;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);

my $DUO_PREFIX  = 'TX';
my $APP_PREFIX  = 'APP';
my $AUTH_PREFIX = 'AUTH';

my $DUO_EXPIRE = 300;
my $APP_EXPIRE = 3600;

my $IKEY_LEN = 20;
my $SKEY_LEN = 40;
my $AKEY_LEN = 40;

our $ERR_USER = 'ERR|The username passed to sign_request() is invalid.';
our $ERR_IKEY = 'ERR|The Duo integration key passed to sign_request() is invalid.';
our $ERR_SKEY = 'ERR|The Duo secret key passed to sign_request() is invalid.';
our $ERR_AKEY = "ERR|The application secret key passed to sign_request() must be at least $AKEY_LEN characters.";
our $ERR_UNKNOWN = 'ERR|An unknown error has occurred.';


sub _sign_vals {
    my ($key, $vals, $prefix, $expire) = @_;

    my $exp = time + $expire;

    my $val = join '|', @{$vals}, $exp;
    my $b64 =encode_base64($val, '');
    my $cookie = "$prefix|$b64";

    my $sig = hmac_sha1_hex($cookie, $key);

    return "$cookie|$sig";
}


sub _parse_vals {
    my ($key, $val, $prefix, $ikey) = @_;

    my $ts = time;

    my @parts = split /\|/, $val;
    if (scalar(@parts) != 3) {
        return '';
    }
    my ($u_prefix, $u_b64, $u_sig) = @parts;

    my $sig = hmac_sha1_hex("$u_prefix|$u_b64", $key);

    if (hmac_sha1_hex($sig, $key) ne hmac_sha1_hex($u_sig, $key)) {
        return '';
    }

    if ($u_prefix ne $prefix) {
        return '';
    }

    my @cookie_parts = split /\|/, decode_base64($u_b64);
    if (scalar(@cookie_parts) != 3) {
        return '';
    }
    my ($user, $u_ikey, $exp) = @cookie_parts;

    if ($u_ikey ne $ikey) {
        return '';
    }

    if ($ts >= $exp) {
        return '';
    }

    return $user;
}

=pod
    Generate a signed request for Duo authentication.
    The returned value should be passed into the Duo.init() call!
    in the rendered web page used for Duo authentication.

    Arguments:

    ikey      -- Duo integration key
    skey      -- Duo secret key
    akey      -- Application secret key
    username  -- Primary-authenticated username
=cut

sub sign_request {
    my ($ikey, $skey, $akey, $username) = @_;

    if (not $username) {
        return $ERR_USER;
    }

    if (index($username, '|') != -1) {
        return $ERR_USER;
    }

    if (not $ikey or length $ikey != $IKEY_LEN) {
        return $ERR_IKEY;
    }

    if (not $skey or length $skey != $SKEY_LEN) {
        return $ERR_SKEY;
    }

    if (not $akey or length $akey < $AKEY_LEN) {
        return $ERR_AKEY;
    }

    my $vals = [ $username, $ikey ];

    my $duo_sig = _sign_vals($skey, $vals, $DUO_PREFIX, $DUO_EXPIRE);
    my $app_sig = _sign_vals($akey, $vals, $APP_PREFIX, $APP_EXPIRE);

    if (not $duo_sig or not $app_sig) {
        return $ERR_UNKNOWN;
    }

    return "$duo_sig:$app_sig";
}

=pod

    Validate the signed response returned from Duo.

    Returns the username of the authenticated user, or '' (empty
    string) if secondary authentication was denied.

    Arguments:

    ikey          -- Duo integration key
    skey          -- Duo secret key
    akey          -- Application secret key
    sig_response  -- The signed response POST'ed to the server

=cut

sub verify_response {
    my ($ikey, $skey, $akey, $sig_response) = @_;

    my ($auth_sig, $app_sig) = split /:/, $sig_response;
    my $auth_user = _parse_vals($skey, $auth_sig, $AUTH_PREFIX, $ikey);
    my $app_user  = _parse_vals($akey, $app_sig, $APP_PREFIX, $ikey);

    if ($auth_user ne $app_user) {
        return '';
    }

    return $auth_user;
}
1;
