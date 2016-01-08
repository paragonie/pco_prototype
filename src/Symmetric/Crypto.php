<?php
declare(strict_types=1);
namespace Php\Crypto\Symmetric;

use Php\Crypto\{
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey,
    Common
};

class Crypto extends Common
{
    /**
     * Message authentication
     * 
     * @param string|resource $source Plaintext (or resource pointing to, e.g., a file)
     * @param AuthenticationKey $masterKey
     * @param array $options
     */
    public function auth($source, AuthenticationKey $masterKey, $options = [])
    {
        return $this->internalDriver->authSymmetric($source, $masterKey, $options);
    }
    
    /**
     * Message authentication
     * 
     * @param string|resource $source Plaintext (or resource pointing to, e.g., a file)
     * @param AuthenticationKey $masterKey
     * @param string $signature
     * @param array $options
     */
    public function verify($source, AuthenticationKey $masterKey, string $signature, $options = [])
    {
        return $this->internalDriver->verifySymmetric($source, $masterKey, $signature, $options);
    }

    /**
     * Encrypt then authenticate a string or resource
     * 
     * @param string|resource $source Plaintext (or resource pointing to, e.g., a file)
     * @param EncryptionKey $masterKey
     * @param array $options
     * 
     * @return string
     */
    public function encrypt($source, EncryptionKey $masterKey, $options = [])
    {
        return $this->internalDriver->encryptSymmetric($source, $masterKey, $options);
    }
    
    /**
     * Verify then decrypt a string all at once
     * 
     * @param string|resource $source Ciphertext (or resource pointing to, e.g., a file)
     * @param EncryptionKey $masterKey
     * @param array $options
     * 
     * @return string
     */
    public function decrypt($source, EncryptionKey $masterKey, $options = [])
    {
        return $this->internalDriver->decryptSymmetric($source, $masterKey, $options);
    }
    
    /**
     * AEAD encryption
     * 
     * @param string $source Plaintext or file/socket resource
     * @param EncryptionKey $masterKey
     * @param string $additional_data Associated Data
     * @param array $options
     * 
     * @return array: [$ciphertext, $additional_data]
     */
    public function aeadEncrypt($source, EncryptionKey $masterKey, string $additional_data = '', $options = [])
    {
        return $this->internalDriver->aeadEncryptSymmetric($source, $masterKey, $additional_data, $options);
    }
    
    /**
     * AEAD decryption
     * 
     * @param string|resource $source Ciphertext or file/socket resource
     * @param EncryptionKey $masterKey
     * @param string $additional_data Associated Data
     * @param array $options
     * 
     * @return string
     */
    public function aeadDecrypt($source, EncryptionKey $masterKey, string $additional_data = '', $options = [])
    {
        return $this->internalDriver->aeadDecryptSymmetric($source, $masterKey, $additional_data, $options);
    }
}
