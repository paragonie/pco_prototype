<?php
namespace Php\Crypto;

use Php\Crypto\Common;

class Asymmetric extends Common
{
    public function __construct($dsn = '')
    {
        parent::__construct($dsn);
        $this->driverID &= 0x80; // We set the first bit to 1 when asymmetric
    }
    
    /**
     * Diffie-Hellman, ECDHE, etc.
     * 
     * Get a shared secret from a private key you possess and a public key for
     * the intended message recipient
     * 
     * @param string $privatekey
     * @param string $publickey
     * @param array $options
     * 
     * @return string
     */
    public function getSharedSecret($privatekey, $publickey, $options = [])
    {
        
    }
    
    /**
     * Encrypt a string using asymmetric cryptography
     * Seal then sign
     * 
     * @param string|resource $source Plaintext (or resource pointing to, e.g., a file)
     * @param string $ourPrivateKey Our private key
     * @param string $theirPublicKey Their public key
     * @param array $options
     * 
     * @return string
     */
    public function encrypt($source, $ourPrivateKey, $theirPublicKey, $options = [])
    {
        
    }
    
    /**
     * Decrypt a string using asymmetric cryptography
     * Verify then unseal
     * 
     * @param string|resource $source Ciphertext (or resource pointing to, e.g., a file)
     * @param string $ourPrivateKey Our private key
     * @param string $theirPublicKey Their public key
     * @param array $options
     * 
     * @return string
     */
    public function decrypt($source, $ourPrivateKey, $theirPublicKey, $options = [])
    {
        
    }
    
    /**
     * Encrypt a message with a target users' public key
     * 
     * @param string|resource $string Message to encrypt (string or resource for a file)
     * @param string $publicKey
     * @param array $options
     * 
     * @return string
     */
    public function seal($source, $publicKey, $options = [])
    {
        
    }
    
    /**
     * Decrypt a sealed message with our private key
     * 
     * @param string $string|resource Encrypted message (string or resource for a file)
     * @param string $privateKey
     * @param array $options
     * 
     * @return string
     */
    public function unseal($source, $privateKey, $options = [])
    {
        
    }
    
    /**
     * Sign a message with our private key
     * 
     * @param string|resource $message Message to sign (string or resource for a file)
     * @param string $privatekey
     * @param array $options
     * 
     * @return string Signature (detached)
     */
    public function sign($message, $privatekey, $options = [])
    {
        
    }
    
    /**
     * Verify a signed message with the correct public key
     * 
     * @param string|resource $message Message to sign (string or resource for a file)
     * @param string $publickey
     * @param string $signature
     * @param array $options
     * 
     * @return boolean
     */
    public function verify($message, $publickey, $signature, $options = [])
    {
        
    }
}
