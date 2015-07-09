<?php
namespace PCO;

class Symmetric extends Common
{
    
    /**
     * Encrypt then authenticate a string or resource
     * 
     * @param string|resource $source Plaintext (or resource pointing to, e.g., a file)
     * @param string $masterKey
     * @param array $options
     * 
     * @return string
     */
    public function encrypt($source, $masterKey, $options = [])
    {
        
    }
    
    /**
     * Verify then decrypt a string all at once
     * 
     * @param string|resource $source Ciphertext (or resource pointing to, e.g., a file)
     * @param string $masterKey
     * @param array $options
     * 
     * @return string
     */
    public function decrypt($source, $masterKey, $options = [])
    {
        
    }
    
    /**
     * AEAD encryption
     * 
     * @param string $source Plaintext or file/socket resource
     * @param string $masterKey
     * @param string $additional_data Associated Data
     * @param array $options
     * 
     * @return array: [$ciphertext, $additional_data]
     */
    public function aeadEncrypt($source, $masterKey, $additional_data = '', $options = [])
    {
        
    }
    
    /**
     * AEAD decryption
     * 
     * @param string|resource $source Ciphertext or file/socket resource
     * @param string $masterKey
     * @param string $additional_data Associated Data
     * @param array $options
     * 
     * @return string
     */
    public function aeadDecrypt($source, $masterKey, $additional_data = '', $options = [])
    {
        
    }
}
