<?php
namespace PCO\Driver;

interface DriverInterface
{
    /**
     * Is the driver loaded?
     * 
     * @return boolean
     */
    public static function isLoaded();
}
