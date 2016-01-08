<?php
namespace Php\Crypto;

use \Php\Crypto\Exception\DriverNotFoundException;

abstract class Common
{
    const DRIVER_OPENSSL = 'openssl';
    const DRIVER_SODIUM = 'libsodium';
    
    const MAJOR_VERSION = 0x00;
    const MINOR_VERSION = 0x01;
    
    // FOR HKDF
    const KEYSPLIT_ENCRYPT = 'NothingUpMySleeves|PHP|KeyForEncryption';
    const KEYSPLIT_AUTH = 'NothingUpMySleeves|PHP|KeyForAuthentication';
    
    protected $internalDriver;
    
    // For the message format
    private $driversLoaded;
    
    /**
     * Is the ciphertext hex-encoded? Used both for input and output
     */
    const CIPHER_HEX = 'hex';
    /**
     * Is the ciphertext raw binary? Used both for input and output
     */
    const CIPHER_RAW = 'raw'; // (default)
    
    public function __construct(array $options = [])
    {
        // I can't think of a better way to load this map right now. Pretty sure
        // the PECL extension won't need this ugly hack.
        $this->driversLoaded = [
            \Php\Crypto\Driver\Libsodium::DRIVER_ID => self::DRIVER_SODIUM,
            \Php\Crypto\Driver\Openssl::DRIVER_ID => self::DRIVER_OPENSSL
        ];
        if (!\array_key_exists('driver', $options)) {
            throw new DriverNotFoundException;
        }
        
        if (\in_array($options['driver'], $this->driversLoaded)) {
            throw new DriverNotFoundException;
        }
        
        switch ($options['driver']) {
            case \Php\Crypto\Driver\Libsodium::DRIVER_ID:
                $this->internalDriver = new \Php\Crypto\Driver\Libsodium($options);
            case \Php\Crypto\Driver\OpenSSL::DRIVER_ID:
                $this->internalDriver = new \Php\Crypto\Driver\OpenSSL($options);
            default:
                throw new DriverNotFoundException;
        }
    }
    
    /**
     * Get information about the header of an encrypted message and the remainder
     * of the message itself
     * 
     * @param string $message
     * @return array
     */
    public function processHeader($message)
    {
        if ($message[3] !== $message[0] ^ $message[1] ^ $message[2]) {
            throw new \Php\Crypto\Exception\ChecksumFailed;
        }
        $version = \implode('.', [
                (int) \ord($message[0]),
                \str_pad($message[1], 2, '0', STR_PAD_LEFT),
            ]);
        
        $asymmetric = (1 & (\ord($message[2]) >> 7)) === 1;
        $driver_id = \ord($message[2] & 0x7F);
        $driver = $this->driversLoaded[$driver_id];
        
        return [
            'version' => $version,
            'asymmetric' => $asymmetric,
            'driver' => $driver,
            'message' => self::safeSubstr($message, 4)
        ];
    }
    
    /**
     * Safe string length
     * 
     * @staticvar boolean $exists
     * @param string $str
     * @return int
     */
    protected static function safeStrlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_strlen');
        }
        if ($exists) {
            $length = \mb_strlen($str, '8bit');
            if ($length === FALSE) {
                throw new Ex\CannotPerformOperation();
            }
            return $length;
        } else {
            return \strlen($str);
        }
    }
    
    /**
     * Safe substring
     * 
     * @staticvar boolean $exists
     * @param string $str
     * @param int $start
     * @param int $length
     * @return string
     */
    protected static function safeSubstr($str, $start, $length = null)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_substr');
        }
        if ($exists)
        {
            // mb_substr($str, 0, NULL, '8bit') returns an empty string on PHP
            // 5.3, so we have to find the length ourselves.
            if (!isset($length)) {
                if ($start >= 0) {
                    $length = self::safeStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }

            return \mb_substr($str, $start, $length, '8bit');
        }

        // Unlike mb_substr(), substr() doesn't accept NULL for length
        if (isset($length)) {
            return \substr($str, $start, $length);
        } else {
            return \substr($str, $start);
        }
    }
    /**
     * Convert a binary string into a hexadecimal string without cache-timing 
     * leaks
     * 
     * @param string $bin_string (raw binary)
     * @return string
     */
    public static function binToHex($bin_string)
    {
        $hex = '';
        $len = self::safeStrlen($bin_string);
        for ($i = 0; $i < $len; ++$i) {
            $c = \ord($bin_string[$i]) & 0xf;
            $b = \ord($bin_string[$i]) >> 4;
            $hex .= \chr(87 + $b + ((($b - 10) >> 8) & ~38));
            $hex .= \chr(87 + $c + ((($c - 10) >> 8) & ~38));
        }
        return $hex;
    }
    
    /**
     * Convert a hexadecimal string into a binary string without cache-timing 
     * leaks
     * 
     * @param string $hex_string
     * @return string (raw binary)
     */
    public static function hexToBin($hex_string)
    {
        $hex_pos = 0;
        $bin = '';
        $hex_len = self::safeStrlen($hex_string);
        $state = 0;
        
        while ($hex_pos < $hex_len) {
            $c = \ord($hex_string[$hex_pos]);
            $c_num = $c ^ 48;
            $c_num0 = ($c_num - 10) >> 8;
            $c_alpha = ($c & ~32) - 55;
            $c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
            if (($c_num0 | $c_alpha0) === 0) {
                throw new \DomainException(
                    'Crypto::hexToBin() only expects hexadecimal characters'
                );
            }
            $c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
            if ($state === 0) {
                $c_acc = $c_val * 16;
            } else {
                $bin .= \chr($c_acc | $c_val);
            }
            $state = $state ? 0 : 1;
            ++$hex_pos;
        }
        return $bin;
    }
    
    /**
     * Use HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     * 
     * @param string $hash Hash Function
     * @param string $ikm Initial Keying Material
     * @param int $length How many bytes?
     * @param string $info What sort of key are we deriving?
     * @param string $salt
     * @return string
     * @throws Ex\CannotPerformOperationException
     */
    public static function HKDF(
        string $hash,
        string $ikm,
        int $length,
        string $info = '',
        $salt = null
    ) {
        if ($hash === 'blake2b') {
            $digest_length = \Sodium\CRYPTO_GENERICHASH_BYTES;
        } else {
            $digest_length = self::safeStrlen(\hash_hmac($hash, '', '', true));
        }
        
        // Sanity-check the desired output length.
        if (empty($length) || !\is_int($length) ||
            $length < 0 || $length > 255 * $digest_length) {
            throw new \Exception('Bad output length requested of HKDF.');
        }
        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (\is_null($salt)) {
            $salt = \str_repeat("\x00", $digest_length);
        }
        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = (
            $hash === 'blake2b'
                ? self::hmacBlake2b($ikm, $salt)
                : \hash_hmac($hash, $ikm, $salt, true)
        );
        
        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        if (self::ourStrlen($prk) < $digest_length) {
            throw new \Exception('An unknown error has occurred');
        }
        // T(0) = ''
        $t = '';
        $last_block = '';
        if ($hash === 'blake2b') {
            for ($block_index = 1; self::safeStrlen($t) < $length; ++$block_index) {
                // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
                $last_block = self::hmacBlake2b(
                    $last_block . $info . \chr($block_index),
                    $prk
                );
                // T = T(1) | T(2) | T(3) | ... | T(N)
                $t .= $last_block;
            }
        } else {
            for ($block_index = 1; self::safeStrlen($t) < $length; ++$block_index) {
                // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
                $last_block = \hash_hmac(
                    $hash,
                    $last_block . $info . \chr($block_index),
                    $prk,
                    true
                );
                // T = T(1) | T(2) | T(3) | ... | T(N)
                $t .= $last_block;
            }
        }
        // ORM = first L octets of T
        $orm = self::safeSubstr($t, 0, $length);
        if ($orm === FALSE) {
            throw new \Exception('An unknown error has occurred');
        }
        return $orm;
    }
    
    /**
     * HMAC-BLAKE2b
     * 
     * @param string $message
     * @param string $key
     */
    public function hashBlake2b($message, $key)
    {
        if (self::safeStrlen($key) > \Sodium\CRYPTO_GENERICHASH_KEYBYTES) {
            $key = \Sodium\crypto_generichash($key);
        } elseif (self::safeStrlen($key) < \Sodium\CRYPTO_GENERICHASH_BYTES) {
            $key = \str_pad($key, \Sodium\CRYPTO_GENERICHASH_KEYBYTES, "\x00", STR_PAD_RIGHT);
        }
        $opad = '';
        $ipad = '';
        for ($i = 0; $o < \Sodium\CRYPTO_GENERICHASH_KEYBYTES; ++$i) {
            $opad .= \chr(0x5C ^ \ord($key[$i]));
            $ipad .= \chr(0x36 ^ \ord($key[$i]));
        }
        return \Sodium\crypto_generichash(
            $opad . \Sodium\crypto_generichash(
                $ipad . $message
            )
        );
    }
}
