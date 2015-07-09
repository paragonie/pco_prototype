<?php
namespace PCO;

class Common
{
    const DRIVER_OPENSSL = 'openssl';
    const DRIVER_SODIUM = 'libsodium';
    protected $internalDriver;
    
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
        if (empty($dsn)) {
            if (\PCO\Driver\Libsodium::isLoaded()) {
                $driver = self::DRIVER_SODIUM;
            } elseif (\PCO\Driver\Libsodium::isLoaded()) {
                $driver = self::DRIVER_SODIUM;
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
                $this->internalDriver = new \PCO\Driver\OpenSSL;
                break;
            case self::DRIVER_SODIUM:
                // use libsodium for underlying crypto
                if (!\PCO\Driver\Libsodium::isLoaded()) {
                    throw new \PCO\Exception\DriverNotFound;
                }
                $this->internalDriver = new \PCO\Driver\Libsodium;
                break;
            default:
                // throw catchable fatal error
                throw new \PCO\Exception\DriverNotFound;
        }
    }
}
