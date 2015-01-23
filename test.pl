#!/usr/bin/env perl

# Simple tests for Duo Web SDK

use strict;
use warnings;
use Test::More 'no_plan';
BEGIN { use_ok 'DuoWeb'; };


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


isnt(DuoWeb::sign_request($IKEY, $SKEY, $AKEY, $USER),
     '',
     'sign_request - Valid sign_request');

is  (DuoWeb::sign_request($IKEY, $SKEY, $AKEY, ''),
     $DuoWeb::ERR_USER,
     'sign_request - Invalid user');

is  (DuoWeb::sign_request($IKEY, $SKEY, $AKEY, 'in|valid'),
     $DuoWeb::ERR_USER,
     'sign_request - Invalid user');

is  (DuoWeb::sign_request('invalid', $SKEY, $AKEY, $USER),
     $DuoWeb::ERR_IKEY,
     'sign_request - Invalid integration key');

is  (DuoWeb::sign_request($IKEY, 'invalid', $AKEY, $USER),
     $DuoWeb::ERR_SKEY,
     'sign_request - Invalid secret key');

is  (DuoWeb::sign_request($IKEY, $SKEY, 'invalid', $USER),
    $DuoWeb::ERR_AKEY,
    'sign_request - Invalid application secret key');

my (undef, $valid_app_sig) = split /:/, DuoWeb::sign_request($IKEY, $SKEY, $AKEY, $USER);
my (undef, $invalid_app_sig) = split /:/, DuoWeb::sign_request($IKEY, $SKEY, 'invalid' x 6, $USER);

is  (DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $INVALID_RESPONSE . ':' . $valid_app_sig),
     '',
     'verify_response - Invalid user');

is  (DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $EXPIRED_RESPONSE . ':' . $valid_app_sig),
     '',
     'verify_response - Expired user');

is  (DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $invalid_app_sig),
     '',
     'verify_response - Future user, invalid app sig');

is  (DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $valid_app_sig),
     $USER,
     'verify_response - Future user');

is  (DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $WRONG_PARAMS_APP),
     '',
     'verify_response - Future user, invalid app sig format');

is  (DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $WRONG_PARAMS_RESPONSE . ':' . $valid_app_sig),
     '',
     'verify_response - Invalid response format');

is  (DuoWeb::verify_response($WRONG_IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $valid_app_sig),
     '',
     'verify_response - Wrong ikey');
