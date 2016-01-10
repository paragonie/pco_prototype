<?php
declare(strict_types=1);
namespace Php\Crypto;


abstract class KeyFactory
{
    /**
     * Return an EncryptionSecretKey and EncryptionPublicKey which are related
     *
     * @param string $driver
     * @return Key[]
     */
    public static function generateEncryptionKeyPair($driver = Common::DRIVER_SODIUM)
    {
        if ($driver === Common::DRIVER_SODIUM) {
            $kp = \Sodium\crypto_box_keypair();
            return [
                new EncryptionSecretKey(
                    \Sodium\crypto_box_secretkey($kp, $driver)
                ),
                new EncryptionPublicKey(
                    \Sodium\crypto_box_publickey($kp, $driver)
                )
            ];
        } elseif ($driver === Common::DRIVER_OPENSSL) {
            $dhres = \openssl_pkey_new([
                'dh' => [
                    'p' => self::GROUP14PRIME,
                    'g' => 2
                ],
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_DH
            ]);
            $details = \openssl_pkey_get_details($dhres);
            return [
                new EncryptionSecretKey(
                    $details['dh']['priv_key'],
                    $driver
                ),
                new EncryptionPublicKey(
                    $details['dh']['pub_key'],
                    $driver
                )
            ];
        }
    }

}