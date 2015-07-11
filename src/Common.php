<?php
namespace PCO;

class Common
{
    const DRIVER_OPENSSL = 'openssl';
    const DRIVER_SODIUM = 'libsodium';
    
    const MAJOR_VERSION = 0x00;
    const MINOR_VERSION = 0x01;
    
    protected $internalDriver;
    
    // For the message format
    private $driver;
    
    /**
     * Is the ciphertext hex-encoded? Used both for input and output
     */
    const CIPHER_HEX = 'hex';
    /**
     * Is the ciphertext raw binary? Used both for input and output
     */
    const CIPHER_RAW = 'raw'; // (default)
    
    public function __construct($dsn = '')
    {
        // I can't think of a better way to load this map right now. Pretty sure
        // the PECL extension won't need this ugly hack.
        $this->driver = [
            \PCO\Driver\Libsodium::DRIVER_ID => self::DRIVER_SODIUM,
            \PCO\Driver\Openssl::DRIVER_ID => self::DRIVER_OPENSSL
        ];
        
        if (empty($dsn)) {
            if (\PCO\Driver\Libsodium::isLoaded()) {
                $driver = self::DRIVER_SODIUM;
            } elseif (\PCO\Driver\OpenSSL::isLoaded()) {
                $driver = self::DRIVER_OPENSSL;
            } else {
                throw new \PCO\Exception\DriverNotFound;
            }
        }
        switch ($driver) {
            case self::DRIVER_OPENSSL:
                // use openssl for underlying crypto
                if (!\PCO\Driver\OpenSSL::isLoaded()) {
                    throw new \PCO\Exception\DriverNotFound;
                }
                $this->driverID = \PCO\Driver\OpenSSL::DRIVER_ID;
                $this->internalDriver = new \PCO\Driver\OpenSSL;
                break;
            case self::DRIVER_SODIUM:
                // use libsodium for underlying crypto
                if (!\PCO\Driver\Libsodium::isLoaded()) {
                    throw new \PCO\Exception\DriverNotFound;
                }
                $this->driverID = \PCO\Driver\Libsodium::DRIVER_ID;
                $this->internalDriver = new \PCO\Driver\Libsodium;
                break;
            default:
                // throw catchable fatal error
                throw new \PCO\Exception\DriverNotFound;
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
            throw new \PCO\Exception\ChecksumFailed;
        }
        $version = \implode('.', [
                (int) \ord($message[0]),
                \str_pad($message[1], 2, '0', STR_PAD_LEFT),
            ]);
        
        $asymmetric = (1 & (\ord($message[2]) >> 7)) === 1;
        $driver_id = \ord($message[2] & 0x7F);
        $driver = $this->driver[$driver_id];
        
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
}
