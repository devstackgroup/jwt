# JWT
[![Latest Stable Version](https://poser.pugx.org/devstackgroup/jwt/v/stable)](https://packagist.org/packages/devstackgroup/jwt) [![Total Downloads](https://poser.pugx.org/devstackgroup/jwt/downloads)](https://packagist.org/packages/devstackgroup/jwt) [![License](https://poser.pugx.org/devstackgroup/jwt/license)](https://packagist.org/packages/devstackgroup/jwt)

JWT (JSON Web Tokens) library for PHP

By [ComStudio](http://comstudio.pl)

Should conform to the [current spec](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06)

## How to use it

### Install with composer

```
$ composer create-project devstackgroup/jwt --stability=dev
```

## Examples
### Creating
```php
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
```
### Verification
```php
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
```
### Getting data
Getting all data
```php
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
	
var_dump($jwt->getHeader(), $jwt->getClaim());
```
Getting specific data
```php
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
	
var_dump($jwt->getHeader('typ'), $jwt->getClaim('iss'));
```
