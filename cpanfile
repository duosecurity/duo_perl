requires 'Digest::HMAC_SHA1', '1.03';
requires 'MIME::Base64', '3.15';

on 'test' => sub {
    requires 'Test::More', '1.302086';
}
