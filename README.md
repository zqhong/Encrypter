# Encrypter － A powerful encrypter library based on illuminate/encryption
The encryption algorithms that Encrypter supports:
* AES-128-CFB
* AES-192-CFB
* AES-256-CFB
* RC4
* RC4-MD5

# Simple
```php
<?php

require __DIR__ . "/vendor/autoload.php";


use Zqhong\Encrypter\Encrypter;

$key = 'password';
$cipher = 'RC4-MD5';
$plainText = 'hello world';
$encrypter = new Encrypter($key, $cipher);

$payload = $encrypter->encryptString($plainText);
echo $payload . PHP_EOL;
echo $encrypter->decryptString($payload) . PHP_EOL;

// will output
//eyJpdiI6IiIsInZhbHVlIjoiMDIxR1dXcHg4K21yR2RBPSIsIm1hYyI6ImRhYzFjYWFjODg5ODA1MWFlMWE0OTZmYTNjMTlkYWIxNDExZjAzYzU2ZjlhM2FmMTY1ZWYwYjFkYTJiZjJkNjgifQ==
//hello world
```