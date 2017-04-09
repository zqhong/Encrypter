<?php

namespace Zqhong\Encrypter\Test;


use PHPUnit\Framework\TestCase;
use Zqhong\Encrypter\Encrypter;

class EncrypterTest extends TestCase
{
    /**
     * @dataProvider provideTestEncryptAndDecrypt
     * @param string $key
     * @param string $cipher
     */
    public function testEncryptAndDecrypt($key, $cipher)
    {
        $plainText = 'hello world';

        $encrypter = new Encrypter($key, $cipher);
        $payload = $encrypter->encryptString($plainText);

        $this->assertEquals($plainText, $encrypter->decryptString($payload));
    }

    /**
     * @return array
     */
    public function provideTestEncryptAndDecrypt()
    {
        return [
            ['password', 'AES-128-CFB'],
            ['password', 'AES-192-CFB'],
            ['password', 'AES-256-CFB'],
            ['password', 'RC4'],
            ['password', 'RC4-MD5'],

            // 超过合法 key 长度的字符都会被删除
            ['long_long_long_long_long_long_long_long_long_long_long_long', 'RC4-MD5'],
            // 虽然 key 为空，但在处理的时候，会使用 paddingChar（默认为 z） 填充
            ['', 'RC4-MD5'],
        ];
    }
}