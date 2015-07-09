<?php
namespace PCO\Driver;

class Libsodium implements DriverInterface
{
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