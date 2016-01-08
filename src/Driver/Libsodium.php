<?php
declare(strict_types=1);
namespace Php\Crypto\Driver;

use Php\Crypto\{
    Asymmetric\EncryptionPublicKey,
    Asymmetric\EncryptionSecretKey,
    Asymmetric\SignaturePublicKey,
    Asymmetric\SignatureSecretKey,
    Common,
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey
};

class Libsodium implements DriverInterface
{
    const DRIVER_ID = 1;
    
    protected $config = [];
    
    public function __construct(array $options = [])
    {
        // LOL NOPE, we use libsodium's defaults!
    }
    
    /**
     * Is the driver loaded?
     * 
     * @return boolean
     */
    public static function isLoaded()
    {
        return extension_loaded('libsodium');
    }
    
    /**
     * Encrypt a message using asymmetric cryptography
     * 
     * @param string|resource $plaintext
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     * @param array $options
     * 
     * @return string
     */
    public function encryptAsymmetric(
        $plaintext,
        EncryptionSecretKey $secretKey = null,
        EncryptionPublicKey $publicKey = null,
        array $options = []
    ): string {
        
    }
    
    /**
     * Decrypt a message using asymmetric cryptography
     * 
     * @param string|resource $ciphertext
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function decryptAsymmetric(
        $ciphertext,
        EncryptionSecretKey $secretKey = null,
        EncryptionPublicKey $publicKey = null,
        array $options = []
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
        $message,
        EncryptionPublicKey $publicKey,
        array $options = []
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
        $sealed,
        EncryptionSecretKey $secretKey,
        array $options = []
    ): string {
        
    }
    
    /**
     * Sign a message, using your secret key
     * 
     * @param string|resource $sealed
     * @param EncryptionPublicKey $publicKey
     * @return string
     */
    public function signAsymmetric(
        $message,
        SignatureSecretKey $secretKey,
        array $options = []
    ): string {
        
    }
    
    /**
     * Sign a message, using your secret key
     * 
     * @param string|resource $sealed
     * @param EncryptionPublicKey $publicKey
     * @param string $signature
     * @return string
     */
    public function verifyAsymmetric(
        string|resource $message, 
        SignaturePublicKey $publicKey,
        string $signature,
        array $options = []
    ): bool {
        
    }
    
    /**
     * Get a shared secret between a Secret Key and a Public Key
     */
    public function getSharedSecret(
        Key $keyA,
        Key $keyB,
        array $options = []
    ): Key {
        
    }
    
    /**
     * Authenticated Encryption with Associated Data (Encrypt)
     * 
     * @param string|resource $plaintext
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
    ): string {
        
    }
    
    
    /**
     * Authenticated Encryption with Associated Data (Decrypt)
     * 
     * @param string|resource $ciphertext
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
    ): string {
        
    }
    
    /**
     * Authenticate a message
     * 
     * @param string|resource $plaintext
     * @param AuthenticationKey $key
     * @return string
     */
    public function authSymmetric(
        $plaintext,
        AuthenticationKey $key,
        array $options = []
    ): string {
        
    }
    
    /**
     * Verify a symmetric-key cryptographic authentication tag
     * 
     * @param string|resource $plaintext
     * @param AuthenticationKey $key
     * @param string $authenticationTag
     * 
     * @return bool
     */
    public function verifySymmetric(
        $plaintext,
        AuthenticationKey $key,
        string $authenticationTag,
        array $options = []
    ): bool {
        
    }
    
    /**
     * Message encryption (secret-key)
     * 
     * @param string|resource $plaintext
     * @param EncryptionKey $key
     * 
     * @return string
     */
    public function encryptSymmetric(
        $plaintext,
        EncryptionKey $key,
        array $options = []
    ): string {
        // Build our header:
            // [VV][VV]:
            $message = \chr(Common::VERSION_MAJOR);
            $message .= \chr(Common::VERSION_MAJOR);
            // [DD]:
            $message .= \chr(0x7F & self::DRIVER_ID);
            // [CC]:
            $message .= \chr(Common::VERSION_MAJOR ^ Common::VERSION_MINOR ^ (0x7F & self::DRIVER_ID));
        
        // Salt:
            $salt = \random_bytes(\Sodium\CRYPTO_GENERICHASH_KEYBYTES);
        
        // Split keys:
            list($encKey, $authKey) = $this->splitSymmetricKey($key, $salt);
            $message .= $salt; // HKDF salt
        
        // Nonce:
            $nonce = \random_bytes(\Sodium\CRYPTO_STREAM_NONCEBYTES);
            $message .= $nonce; // Nonce for the stream cipher
        
        // Encrypt:
            $message .= \Sodium\crypto_stream_xor(
                $plaintext,
                $nonce,
                $encKey->getRawBytes()
            );
            unset($encKey);
        
        // Authenticate:
            $message .= \Sodium\crypto_auth($message, $authKey->getRawBytes());
            unset($authKey);
        
        // Return:
        return $message;
    }

    /**
     * Message decryption (secret-key)
     * 
     * @param string|resource $plaintext
     * @param EncryptionKey $key
     * 
     * @return string
     */
    public function decryptSymmetric(
        $ciphertext,
        EncryptionKey $key,
        array $options = []
    ): string {
        
    }
    
    /**
     * Split a key (i.e. master key -> encryption key, authentication key)
     * 
     * @return Key[]
     */
    public function splitSymmetricKey(
        Key $key
        string $salt
    ): array {
        return [
            new EncryptionKey(
                Common::HKDF(
                    'blake2b',
                    $key->getRawBytes(),
                    \Sodium\CRYPTO_STREAM_KEYBYTES,
                    Common::KEYSPLIT_ENCRYPT,
                    $salt
                ),
                Common::DRIVER_SODIUM
            ),
            
            new AuthenticationKey(
                Common::HKDF(
                    'blake2b',
                    $key->getRawBytes(),
                    \Sodium\CRYPTO_AUTH_KEYBYTES,
                    Common::KEYSPLIT_AUTH,
                    $salt
                ),
                Common::DRIVER_SODIUM
            )
        ];
    }
}