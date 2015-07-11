<?php
namespace PCO\Driver;

class Libsodium implements DriverInterface
{
    const DRIVER_ID = 1;
    
    /**
     * Is the driver loaded?
     * 
     * @return boolean
     */
    public static function isLoaded()
    {
        return extension_loaded('libsodium');
    }
}