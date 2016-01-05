<?php
namespace Php\Crypto;

class Key
{
    protected $driver;
    private $keyMaterial;
    
    /**
     * 
     * @param string $keyMaterial
     * @param int $driver
     */
    public function __construct($keyMaterial = null, $driver = Common::DRIVER_SODIUM)
    {
        $this->keyMaterial = $keyMaterial;
        $this->driver = $driver;
    }
    
    /**
     * A string of raw binary
     * 
     * @return string
     */
    public function getRawBytes()
    {
        return $this->keyMaterial;
    }
}
