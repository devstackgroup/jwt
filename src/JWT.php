<?php

namespace JWT;

use \DomainException;
use \InvalidArgumentException;
use \UnexpectedValueException;
use \DateTime;

final class JWT
{
	public static $supportedAlg = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512']
    ];

    private static $exp = 0;

    private $headers = [];

    private static $algorithm;

    private $claims = [];

    private $signature = null;

    public function __construct($algorithm = 'HS256')
    {
    	$this->headers = ['typ'=> 'JWT', 'alg' => $algorithm];
        JWT::$algorithm = $algorithm;
    }

    public function sign($key, $algorithm = null)
    {
    	$payload = $this->getPayload();
        $algorithm = empty($algorithm) ? self::getAlgorithm() : $algorithm;

    	if (empty(self::$supportedAlg[$algorithm])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = self::$supportedAlg[$algorithm];

        switch($function) {
            case 'hash_hmac':
                $this->signature = hash_hmac($algorithm, $payload, $key, true);

                return $this;
            case 'openssl':
                $signature = '';
                $success = openssl_sign($payload, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to sign data");
                } else {
                    $this->signature = $signature;

                    return $this;
                }
        }
    }

    public function getToken()
    {
        $payload = [$this->getPayload()];

        if ($this->signature !== null) {
            $payload[] = JWT::URLSafeB64Encode($this->signature);
        }

        return implode('.', $payload);
    }

    public function verifyToken($key, $token = null)
    {
        if(empty($token)){
            $token = $this;
        } 
        
        if($token instanceof JWT){
            $token = $token->getToken();
        }

        if (empty($key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }

        $token = explode('.', $token);

        if (count($token) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headB64, $payloadB64, $cryptoB64) = $token;

        if (null === ($header = JWT::jsonDecode(JWT::URLSafeB64Decode($headB64)))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }

        if (null === $payload = JWT::jsonDecode(JWT::URLSafeB64Decode($payloadB64))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }

        $sign = JWT::URLSafeB64Decode($cryptoB64);

        if (empty($header->alg) || $header->alg === 'none') {
            throw new DomainException('Empty algorithm');
        }

        if (empty(self::$supportedAlg[$header->alg])) {
            throw new DomainException('Algorithm not supported');
        }

        if (is_array($key) || $key instanceof \ArrayAccess) {
            if (isset($header->kid)) {
                $key = $key[$header->kid];
            } else {
                throw new DomainException('"kid" empty, unable to lookup correct key');
            }
        }

        if (!JWT::verify("$headB64.$payloadB64", $sign, $key, $header->alg)) {
            return false;
        }

        if (isset($payload->nbf) && $payload->nbf > (time() + self::$exp)) {
            throw new BeforeValidException(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf)
            );
        }

        if (isset($payload->iat) && $payload->iat > (time() + self::$exp)) {
            throw new BeforeValidException(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat)
            );
        }

        if (isset($payload->exp) && (time() - self::$exp) >= $payload->exp) {
            throw new ExpiredException('Expired token');
        }

        return true;
    }

    public function getHeader($key = null)
    {
        if(!empty($key) && array_key_exists($key, $this->headers)) {
            return $this->headers[$key];
        } elseif(!empty($key) && !array_key_exists($key, $this->headers)) {
            throw new InvalidArgumentException('Invalid header argument');
        }

        return $this->headers;
    }

    public function getClaim($key = null)
    {
        if(!empty($key) && array_key_exists($key, $this->claims)) {
            return $this->claims[$key];
        } elseif(!empty($key) && !array_key_exists($key, $this->claims)) {
            throw new InvalidArgumentException('Invalid claim argument');
        }

        return $this->claims;
    }


    public function setIssuer($issuer)
    {
    	return $this->setClaim('iss', (string) $issuer);
    }

	public function setAudience($audience)
	{
		return $this->setClaim('aud', (string) $audience);
	}

	public function setIssuedAt($issuedAt)
    {
        return $this->setClaim('iat', (int) $issuedAt);
    }

    public function setNotBefore($notBefore)
    {
      	return $this->setClaim('nbf', (int) $notBefore);
    }

    public function setTimeOut($timeOut)
    {
        self::$exp = $timeOut;
    }

    public function setClaim($key,$value)
    {
    	$this->claims[$key] = $value;

    	return $this;
    }

    private function getPayload()
    {
    	$payload = [
            JWT::URLSafeB64Encode(JWT::jsonEncode($this->headers)),
            JWT::URLSafeB64Encode(JWT::jsonEncode($this->claims))
        ];

        return implode('.', $payload);
    }

    private static function verify($payload, $signature, $key, $algorithm)
    {
        if (empty(self::$supportedAlg[$algorithm])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = self::$supportedAlg[$algorithm];

        switch($function) {
            case 'openssl':
                $success = openssl_verify($payload, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to verify data: " . openssl_error_string());
                } else {
                    return $signature;
                }
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $payload, $key, true);

                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }

                $len = min(self::safeStrlen($signature), self::safeStrlen($hash));
                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= (self::safeStrlen($signature) ^ self::safeStrlen($hash));

                return ($status === 0);
        }
    }

    private static function getAlgorithm()
    {
    	return !empty(JWT::$algorithm) ? JWT::$algorithm : 'none';
    }

    private static function safeStrlen($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }

        return strlen($str);
    }

    private static function URLSafeB64Encode($data)
    {
        $base64 = base64_encode($data);
        $base64 = str_replace(['+', '/', '\r', '\n', '='], ['-', '_'], $base64);

        return $base64;
    }

    private static function URLSafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;

        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }

    private static function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }

        return $json;
    }

    private static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            $object = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            $maxIntLength = strlen((string) PHP_INT_MAX) - 1;
            $jsonWithoutBigints = preg_replace('/:\s*(-?\d{'.$maxIntLength.',})/', ': "$1"', $input);
            $object = json_decode($jsonWithoutBigints);
        }
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } elseif ($object === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }

        return $object;
    }

    private static function handleJsonError($errno)
    {
        $msg = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        ];
        throw new DomainException(
            isset($msg[$errno])
            ? $msg[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }
}
