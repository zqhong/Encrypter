<?php

namespace Zqhong\Encrypter;

use RuntimeException;
use Zqhong\Encrypter\Exceptions\DecryptException;
use Zqhong\Encrypter\Exceptions\EncryptException;

class Encrypter implements EncrypterContract
{
    /**
     * 加密 key
     *
     * @var string
     */
    protected $key;

    /**
     * 加密算法
     *
     * @var string
     */
    protected $cipher;

    /**
     * 填充字符，当 $this->key 的长度不足时，使用 $this->paddingChar 指定的字符填充
     *
     * @var string
     */
    protected $paddingChar = 'z';

    /**
     * 所有支持的加密算法数组
     *
     * @var array
     */
    protected static $supportedCipher = [
        'AES-128-CFB' => [
            'keyLen' => 16,
            'ivSize' => 16,
        ],
        'AES-192-CFB' => [
            'keyLen' => 24,
            'ivSize' => 16,
        ],
        'AES-256-CFB' => [
            'keyLen' => 32,
            'ivSize' => 16,
        ],
        'RC4' => [
            'keyLen' => 16,
            'ivSize' => 0,
        ],
        'RC4-MD5' => [
            'keyLen' => 16,
            'ivSize' => 0,
        ],
    ];

    /**
     * 创建一个新的 Encrypter 实例
     *
     * @param  string $key
     * @param  string $cipher
     */
    public function __construct($key, $cipher = 'AES-256-CFB')
    {
        $key = (string)$key;

        if (static::supported($cipher)) {
            $this->cipher = strtoupper($cipher);
            $this->key = $this->formatKey($key);

            $this->init();
        } else {
            throw new RuntimeException('The cipher is not supported.');
        }
    }

    protected function init()
    {
        if ($this->cipher === 'RC4-MD5') {
            // openssl 仅支持 RC4，这里需要 hack 一下
            $this->key = md5($this->key);
            $this->cipher = 'RC4';
        }
    }

    /**
     * 部分加密算法对 key 的长度有限制
     * 当 $key 的长度大于当前加密算法指定的长度时，formatKey 方法会删除多余的字符；
     * 当 $key 的长度小于当前加密算法指定的长度时，formatKey 方法会使用 $this->paddingChar 字符填充
     *
     * @param string $key
     * @return string
     */
    protected function formatKey($key)
    {
        $currentKeyLen = mb_strlen($key, '8bit');
        $correctKeyLen = $this->getCorrectKeyLen();

        if ($currentKeyLen < $correctKeyLen) {
            $key = $key . str_repeat($this->paddingChar, $correctKeyLen - $currentKeyLen);
        } elseif ($currentKeyLen > $correctKeyLen) {
            $key = mb_substr($this->key, 0, $correctKeyLen, '8bit');
        }

        return $key;
    }

    /**
     * 检查所给的 cipher 是否合法
     *
     * @param  string $cipher
     * @return bool
     */
    public static function supported($cipher)
    {
        return isset(static::$supportedCipher[$cipher]);
    }

    /**
     * 加密所给的数据
     *
     * @param  mixed $value
     * @param  bool $serialize
     * @return string
     *
     */
    public function encrypt($value, $serialize = true)
    {
        $iv = '';
        $ivSize = $this->getIvSize();
        if ($ivSize > 0) {
            $iv = random_bytes($ivSize);
        }

        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        $value = \openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher, $this->key, 0, $iv
        );

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        // Once we have the encrypted value we will go ahead base64_encode the input
        // vector and create the MAC for the encrypted value so we can verify its
        // authenticity. Then, we'll JSON encode the data in a "payload" array.
        $mac = $this->hash($iv = base64_encode($iv), $value);

        $json = json_encode(compact('iv', 'value', 'mac'));

        if (!is_string($json)) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param  string $value
     * @return string
     */
    public function encryptString($value)
    {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypt the given value.
     *
     * @param  mixed $payload
     * @param  bool $unserialize
     * @return string
     *
     */
    public function decrypt($payload, $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);

        $iv = base64_decode($payload['iv']);

        // Here we will decrypt the value. If we are able to successfully decrypt it
        // we will then unserialize it and return it out to the caller. If we are
        // unable to decrypt this value we will throw out an exception message.
        $decrypted = \openssl_decrypt(
            $payload['value'], $this->cipher, $this->key, 0, $iv
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param  string $payload
     * @return string
     */
    public function decryptString($payload)
    {
        return $this->decrypt($payload, false);
    }

    /**
     * Create a MAC for the given value.
     *
     * @param  string $iv
     * @param  mixed $value
     * @return string
     */
    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }

    /**
     * Get the JSON array from the given payload.
     *
     * @param  string $payload
     * @return array
     *
     */
    protected function getJsonPayload($payload)
    {
        $payload = json_decode(base64_decode($payload), true);

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (!$this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        if (!$this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }

        return $payload;
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param  mixed $payload
     * @return bool
     */
    protected function validPayload($payload)
    {
        return is_array($payload) && isset(
            $payload['iv'], $payload['value'], $payload['mac']
        );
    }

    /**
     * Determine if the MAC for the given payload is valid.
     *
     * @param  array $payload
     * @return bool
     */
    protected function validMac(array $payload)
    {
        $calculated = $this->calculateMac($payload, $bytes = random_bytes(16));

        return hash_equals(
            hash_hmac('sha256', $payload['mac'], $bytes, true), $calculated
        );
    }

    /**
     * Calculate the hash of the given payload.
     *
     * @param  array $payload
     * @param  string $bytes
     * @return string
     */
    protected function calculateMac($payload, $bytes)
    {
        return hash_hmac(
            'sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true
        );
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return int
     */
    protected function getIvSize()
    {
        return static::$supportedCipher[$this->cipher]['ivSize'];
    }

    /**
     * @return int
     */
    protected function getCorrectKeyLen()
    {
        return static::$supportedCipher[$this->cipher]['keyLen'];
    }
}