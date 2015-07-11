<?php
namespace PCO\Driver;

class OpenSSL implements DriverInterface
{
    const DRIVER_ID = 2;
    
    /**
     * Is the driver loaded?
     * 
     * @return boolean
     */
    public static function isLoaded()
    {
        return extension_loaded('openssl');
    }
}