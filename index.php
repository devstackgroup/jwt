<?php

require 'vendor/autoload.php';

use JWT\JWT;

$jwt = new JWT();

$jwt->setIssuer('http://example.com')
	->setAudience('http://example.org')
	->setIssuedAt(time())
	->setNotBefore(time() + 60)
	->sign('secret')
	->getToken();

var_dump($jwt->verifyToken('secret'));

var_dump($jwt->getHeader('typ'), $jwt->getClaim('iss'));
