#!/usr/bin/env perl

# Simple tests for Duo Web SDK

use Test::More;
use strict;
use warnings;

plan(tests => 14);

use_ok('Duo::Web');

my $IKEY = "DIXXXXXXXXXXXXXXXXXX";
my $WRONG_IKEY = "DIXXXXXXXXXXXXXXXXXY";
my $SKEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
my $AKEY = "useacustomerprovidedapplicationsecretkey";

my $USER = "testuser";

my $INVALID_RESPONSE = "AUTH|INVALID|SIG";
my $EXPIRED_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702";
my $FUTURE_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef";
my $WRONG_PARAMS_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|6cdbec0fbfa0d3f335c76b0786a4a18eac6cdca7";
my $WRONG_PARAMS_APP = "APP|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|7c2065ea122d028b03ef0295a4b4c5521823b9b5";

my (undef, $VALID_APP_SIG) = split /:/, Duo::Web::sign_request($IKEY, $SKEY, $AKEY, $USER);
my (undef, $INVALID_APP_SIG) = split /:/, Duo::Web::sign_request($IKEY, $SKEY, 'invalid' x 6, $USER);

isnt(
    Duo::Web::sign_request($IKEY, $SKEY, $AKEY, $USER),
    '',
    'sign_request - Valid sign_request'
);

is(
    Duo::Web::sign_request($IKEY, $SKEY, $AKEY, ''),
    $Duo::Web::ERR_USER,
    'sign_request - Invalid user'
);

is(
    Duo::Web::sign_request($IKEY, $SKEY, $AKEY, 'in|valid'),
    $Duo::Web::ERR_USER,
    'sign_request - Invalid user'
);

{
    # Squelch 'Name "Duo::Web::ERR_IKEY" used only once: possible typo'
    no warnings 'once';
    is(
        Duo::Web::sign_request('invalid', $SKEY, $AKEY, $USER),
        $Duo::Web::ERR_IKEY,
        'sign_request - Invalid integration key'
    );
}

{
    # Squelch 'Name "Duo::Web::ERR_SKEY" used only once: possible typo'
    no warnings 'once';
    is(
        Duo::Web::sign_request($IKEY, 'invalid', $AKEY, $USER),
        $Duo::Web::ERR_SKEY,
        'sign_request - Invalid secret key'
    );
}

{
    # Squelch 'Name "Duo::Web::ERR_AKEY" used only once: possible typo'
    no warnings 'once';
    is(
        Duo::Web::sign_request($IKEY, $SKEY, 'invalid', $USER),
        $Duo::Web::ERR_AKEY,
        'sign_request - Invalid application secret key'
    );
}

is(
    Duo::Web::verify_response($IKEY, $SKEY, $AKEY, $INVALID_RESPONSE . ':' . $VALID_APP_SIG),
    '',
    'verify_response - Invalid user'
);

is(
    Duo::Web::verify_response($IKEY, $SKEY, $AKEY, $EXPIRED_RESPONSE . ':' . $VALID_APP_SIG),
    '',
    'verify_response - Expired user'
);

is(
    Duo::Web::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $INVALID_APP_SIG),
    '',
    'verify_response - Future user, invalid app sig');

is(
    Duo::Web::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $VALID_APP_SIG),
    $USER,
    'verify_response - Future user'
);

is(
    Duo::Web::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $WRONG_PARAMS_APP),
    '',
    'verify_response - Future user, invalid app sig format'
);

is(
    Duo::Web::verify_response($IKEY, $SKEY, $AKEY, $WRONG_PARAMS_RESPONSE . ':' . $VALID_APP_SIG),
    '',
    'verify_response - Invalid response format'
);

is(
    Duo::Web::verify_response($WRONG_IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $VALID_APP_SIG),
    '',
    'verify_response - Wrong ikey'
);
