<?php
namespace Php\Crypto\Driver;

use Php\Crypto\{
    Asymmetric\EncryptionPublicKey,
    Asymmetric\EncryptionSecretKey,
    Asymmetric\SignaturePublicKey,
    Asymmetric\SignatureSecretKey,
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey,
    Common,
    Key,
    KeyFactory
};

interface DriverInterface
{
    /**
     * Is the driver loaded?
     * 
     * @return boolean
     */
    public static function isLoaded();
    
    /**
     * Encrypt a message using asymmetric cryptography
     * 
     * @param string $plaintext
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     */
    public function encryptAsymmetric(
        $plaintext,
        EncryptionSecretKey $secretKey = null,
        EncryptionPublicKey $publicKey = null,
        array $options = []
    ): string;
    
    /**
     * Decrypt a message using asymmetric cryptography
     * 
     * @param string $ciphertext
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function decryptAsymmetric(
        $ciphertext,
        EncryptionSecretKey $secretKey = null,
        EncryptionPublicKey $publicKey = null,
        array $options = []
    ): string;
    
    /**
     * Seal a message, using only the recipient's public key.
     * 
     * @param string $message
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function sealAsymmetric(
        $message,
        EncryptionPublicKey $publicKey,
        array $options = []
    ): string;
    
    /**
     * Unseal a message, using your secret key
     * 
     * @param string $sealed
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function unsealAsymmetric(
        $sealed,
        EncryptionSecretKey $secretKey,
        array $options = []
    ): string;
    
    /**
     * Sign a message, using your secret key
     * 
     * @param string $sealed
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function signAsymmetric(
        $message,
        SignatureSecretKey $secretKey,
        array $options = []
    ): string;
    
    /**
     * Sign a message, using your secret key
     * 
     * @param string $sealed
     * @param EncryptionPublicKey $publicKey
     * @param string $signature
     * @return string
     */
    public function verifyAsymmetric(
        $message,
        SignaturePublicKey $publicKey,
        string $signature,
        array $options = []
    ): bool;
    
    /**
     * Get a shared secret between a Secret Key and a Public Key
     */
    public function getSharedSecret(
        Key $keyA,
        Key $keyB,
        array $options = []
    ): Key;
    
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
        $plaintext,
        string $ad = '',
        EncryptionKey $key,
        array $options = []
    ): string;
    
    
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
        $ciphertext,
        string $ad = '',
        EncryptionKey $key,
        array $options = []
    ): string;
    
    /**
     * Authenticate a message
     * 
     * @param string $plaintext
     * @param AuthenticationKey $key
     * @return string
     */
    public function authSymmetric(
        $plaintext,
        AuthenticationKey $key,
        array $options = []
    ): string;
    
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
        $plaintext,
        AuthenticationKey $key,
        string $authenticationTag,
        array $options = []
    ): bool;
    
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
        EncryptionKey $key,
        array $options = []
    ): string;

    /**
     * Message decryption (secret-key)
     * 
     * @param string $plaintext
     * @param EncryptionKey $key
     * 
     * @return string
     */
    public function decryptSymmetric(
        $ciphertext,
        EncryptionKey $key,
        array $options = []
    ): string;
    
    /**
     * Split a key (i.e. master key -> encryption key, authentication key)
     * 
     * @return Key[]
     */
    public function splitSymmetricKey(
        Key $key,
        string $salt
    ): array;
}
