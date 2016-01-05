<?php
namespace Php\Crypto\Driver;

use Php\Crypto\{
    Asymmetric\EncryptionPublicKey,
    Asymmetric\EncryptionSecretKey,
    Asymmetric\SignaturePublicKey,
    Asymmetric\SignatureSecretKey,
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey
};

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
    
    /**
     * Encrypt a message using asymmetric cryptography
     * 
     * @param string $plaintext
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     */
    public function encryptAsymmetric(
        string $plaintext,
        EncryptionSecretKey $secretKey = null, 
        EncryptionPublicKey $publicKey = null
    ): string {
        
    }
    
    /**
     * Decrypt a message using asymmetric cryptography
     * 
     * @param string $ciphertext
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function decryptAsymmetric(
        string $ciphertext,
        EncryptionSecretKey $secretKey = null,
        EncryptionPublicKey $publicKey = null
    ): string {
        
    }
    
    /**
     * Seal a message, using only the recipient's public key.
     * 
     * @param string $message
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function sealAsymmetric(
        string $message,
        EncryptionPublicKey $publicKey
    ): string {
        
    }
    
    /**
     * Unseal a message, using your secret key
     * 
     * @param string $sealed
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function unsealAsymmetric(
        string $sealed,
        EncryptionSecretKey $secretKey
    ): string {
        
    }
    
    /**
     * Sign a message, using your secret key
     * 
     * @param string $sealed
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function signAsymmetric(
        string $message,
        SignatureSecretKey $secretKey
    ): string {
        
    }
    
    /**
     * Sign a message, using your secret key
     * 
     * @param string $sealed
     * @param EncryptionPublicKey $publicKey
     * @param string $signature
     * @return string
     */
    public function verifyAsymmetric(
        string $message, 
        SignaturePublicKey $publicKey,
        string $signature
    ): bool {
        
    }
    
    /**
     * Get a shared secret between a Secret Key and a Public Key
     */
    public function getSharedSecret(
        Key $keyA,
        Key $keyB
    ): Key {
        
    }
    
    /**
     * Authenticated Encryption with Associated Data (Encrypt)
     * 
     * @param string $plaintext
     * @param string $ad
     * @param EncryptionKey $key
     * 
     * @return string
     */
    public function aeadEncryptSymmetric(
        string $plaintext,
        string $ad = '',
        EncryptionKey $key
    ): string {
        
    }
    
    
    /**
     * Authenticated Encryption with Associated Data (Decrypt)
     * 
     * @param string $plaintext
     * @param string $ad
     * @param EncryptionKey $key
     * 
     * @return string
     */
    public function aeadDecryptSymmetric(
        string $ciphertext,
        string $ad = '',
        EncryptionKey $key
    ): string {
        
    }
    
    /**
     * Authenticate a message
     * 
     * @param string $plaintext
     * @param AuthenticationKey $key
     * @return string
     */
    public function authSymmetric(
        string $plaintext,
        AuthenticationKey $key
    ): string {
        
    }
    
    /**
     * Verify a symmetric-key cryptographic authentication tag
     * 
     * @param string $plaintext
     * @param AuthenticationKey $key
       @param string $authenticationTag
     * 
     * @return bool
     */
    public function verifySymmetric(
        string $plaintext,
        AuthenticationKey $key,
        string $authenticationTag
    ): bool {
        
    }
    
    /**
     * Message encryption (secret-key)
     * 
     * @param string $plaintext
     * @param EncryptionKey $key
     * 
     * @return string
     */
    public function encryptSymmetric(
        $plaintext,
        EncryptionKey $key
    ): string {
        
    }

    /**
     * Message decryption (secret-key)
     * 
     * @param string $plaintext
     * @param EncryptionKey $key
     * 
     * @return string
     */
    public function decryptSymmetric(
        string $ciphertext,
        EncryptionKey $key
    ): string {
        
    }
}