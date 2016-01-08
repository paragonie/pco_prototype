<?php
declare(strict_types=1);
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
    
    protected $config = [
        'cipher' => 'aes-256',
        'hash' => 'sha-384'
    ];
    
    public function __construct(array $options = [])
    {
        if (!empty($options)) {
            $this->config = $options;
        }
        if (!\in_array($this->config['cipher'].'-ctr', \openssl_get_cipher_methods())) {
            throw new Error('Cipher '.$this->config['cipher'].'-ctr'.' not found!');
        }
    }
    
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
     * @param string|resource $plaintext
     * @param EncryptionSecretKey $secretKey
     * @param EncryptionPublicKey $publicKey
     */
    public function encryptAsymmetric(
        $plaintext,
        EncryptionSecretKey $secretKey = null, 
        EncryptionPublicKey $publicKey = null,
        array $options = []
    ): string {
        $sharedSecret = $this->getSharedSecret($secretKey, $publicKey);
        return $this->encryptSymmetric(
            $plaintext,
            $sharedSecret,
            $options
        );
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
        $sharedSecret = $this->getSharedSecret($secretKey, $publicKey);
        return $this->decryptSymmetric(
            $ciphertext,
            $sharedSecret,
            $options
        );
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
        /**
         * 1. Generate a random DH private key.
         * 2. Calculate the shared secret.
         * 3. Encrypt with symmetric-key crypto.
         * 4. Authenticate.
         */
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
        /**
         * 1. Read public key from ciphertext.
         * 2. Calculate the shared secret with our secret key.
         * 3. Verify authentication tag.
         * 3. Decrypt with symmetric-key crypto.
         */
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
        # openssl_sign()
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
        # openssl_verify()
    }
    
    /**
     * Get a shared secret between a Secret Key and a Public Key
     */
    public function getSharedSecret(
        Key $keyA,
        Key $keyB,
        array $options = []
    ): Key {
        # Diffie Hellman, 2048-bit (group 14)
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
        # AES-GCM but good luck getting that to work in PHP-land
        
        throw new Error('Pah! You wish! Dream on.');
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
        # AES-GCM but good luck getting that to work in PHP-land
        
        throw new Error('Pah! You wish! Dream on.');
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
        return \hash_hmac(
            $this->config['hash'], 
            $message,
            $key->getRawBytes(),
            true
        );
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
        # Verify HMAC-SHA2
        return \hash_equals(
            $this->authSymmetric($plaintext, $key, $options),
            $authenticationTag
        );
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
            // [DD]: Make sure leftmost bit is 0 because we're symmetric
            $message .= \chr(0x7F & self::DRIVER_ID);
            // [CC]:
            $message .= \chr(Common::VERSION_MAJOR ^ Common::VERSION_MINOR ^ (0x7F & self::DRIVER_ID));
        
        // Salt:
            $salt = \random_bytes(
                Common::safeStrlen(\hash($this->config['hash'], '', true))
            );
        
        // Split keys:
            list($encKey, $authKey) = $this->splitSymmetricKey($key, $salt);
            $message .= $salt; // HKDF salt
        
        // Nonce:
            $nonce = \random_bytes(\openssl_cipher_iv_length($this->config['cipher']));
            $message .= $nonce; // Nonce for the stream cipher
        
        // Encrypt:
            $message .= \openssl_encrypt(
                $plaintext,
                $this->config['cipher'] . '-ctr',
                $encKey->getRawBytes(),
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
                $nonce
            );
            unset($encKey);
        
        // Authenticate:
            $message .= \hash_hmac(
                $this->config['hash'], 
                $message,
                $authKey->getRawBytes(),
                true
            );
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
        # Verify then Decrypt, HMAC-SHA2 then AES-CTR
        
        # openssl_decrypt
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
                    $this->config['hash'],
                    $key->getRawBytes(),
                    $this->getKeySize(),
                    Common::KEYSPLIT_ENCRYPT,
                    $salt
                ),
                Common::DRIVER_SODIUM
            ),
            
            new AuthenticationKey(
                Common::HKDF(
                    $this->config['hash'],
                    $key->getRawBytes(),
                    Common::safeStrlen(\hash($this->config['hash'], '', true)),
                    Common::KEYSPLIT_AUTH,
                    $salt
                ),
                Common::DRIVER_SODIUM
            )
        ];
    }
    
    /**
     * Get the appropriate key size, in bytes, for the current cipher.
     */
    protected function getKeySize(): int
    {
        switch ($this->config['cipher']) {
            case 'aes-256':
                return 32;
            case 'aes-192':
                return 24;
            case 'aes-128':
                return 16;
            default:
                throw new Error('Invalid encryption algorithm');
        }
    }
}