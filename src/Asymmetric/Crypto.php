<?php
declare(strict_types=1);
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
     * @param Key $secretKey
     * @param Key $publicKey
     * @param array $options
     * 
     * @return string
     */
    public function getSharedSecret(Key $secretKey, Key $publicKey, $options = [])
    {
        return $this->internalDriver->getSharedSecret($secretKey, $publicKey, $options);
    }
    
    /**
     * Encrypt a string using asymmetric cryptography
     * Seal then sign
     * 
     * @param string|resource $source Plaintext (or resource pointing to, e.g., a file)
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     * @param array $options
     * 
     * @return string
     */
    public function encrypt(
        $source,
        EncryptionSecretKey $secretKey = null,
        EncryptionPublicKey $publicKey = null,
        $options = []
    ) {
        return $this->internalDriver->encryptAsymmetric(
            $source,
            $secretKey,
            $publicKey,
            $options
        );
    }
    
    /**
     * Decrypt a string using asymmetric cryptography
     * Verify then unseal
     * 
     * @param string|resource $source Ciphertext (or resource pointing to, e.g., a file)
     * @param EncryptionSecretKey $secretKey Our secret key
     * @param EncryptionPublicKey $publicKey the other party's public key
     * @param array $options
     * 
     * @return string
     */
    public function decrypt(
        $source,
        EncryptionSecretKey $secretKey = null,
        EncryptionPublicKey $publicKey = null,
        $options = []
    ) {
        return $this->internalDriver->decryptAsymmetric(
            $source,
            $secretKey,
            $publicKey,
            $options
        );
    }
    
    /**
     * Encrypt a message with a target users' public key
     * 
     * @param string|resource $source Message to encrypt (string or resource for a file)
     * @param EncryptionPublicKey $publicKey the other party's public key
     * @param array $options
     * 
     * @return string
     */
    public function seal($source, EncryptionPublicKey $publicKey, $options = [])
    {
        return $this->internalDriver->seal($source, $publicKey, $options);
    }
    
    /**
     * Decrypt a sealed message with our private key
     * 
     * @param string|resource $source Encrypted message (string or resource for a file)
     * @param EncryptionSecretKey $secretKey Our secret key
     * @param array $options
     * 
     * @return string
     */
    public function unseal($source, EncryptionSecretKey $secretKey, $options = [])
    {
        return $this->internalDriver->unseal($source, $secretKey, $options);
    }
    
    /**
     * Sign a message with our private key
     * 
     * @param string|resource $message Message to sign (string or resource for a file)
     * @param SignatureSecretKey $privateKey
     * @param array $options
     * 
     * @return string Signature (detached)
     */
    public function sign($message, SignatureSecretKey $privateKey, $options = [])
    {
        return $this->internalDriver->sign($message, $privateKey, $options);
    }
    
    /**
     * Verify a signed message with the correct public key
     * 
     * @param string|resource $message Message to sign (string or resource for a file)
     * @param string $publickey
     * @param string $signature
     * @param array $options
     * 
     * @return bool
     */
    public function verify($message, SignaturePublicKey $publicKey, string $signature, $options = [])
    {
        return $this->internalDriver->verify($message, $publicKey, $signature, $options);
    }
}
