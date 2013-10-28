<?php
/**
 * This file is part of the XmlSecurity library. It is a library written in PHP
 * for working with XML Encryption and Signatures.
 *
 * Large portions of the library are derived from the xmlseclibs PHP library for
 * XML Security (http://code.google.com/p/xmlseclibs/) Copyright (c) 2007-2010,
 * Robert Richards <rrichards@cdatazone.org>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author  Andreas Schamberger <mail@andreass.net>
 * @author  Robert Richards <rrichards@cdatazone.org>
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 */

namespace ass\XmlSecurity\Key;

use ass\XmlSecurity\Key;
use ass\XmlSecurity\Exception\InvalidArgumentException;
use ass\XmlSecurity\Exception\DecryptionException;
use ass\XmlSecurity\Exception\EncryptionException;

/**
 * This class holds a security key and provides the necessary encryption,
 * decryption and certificate handling routines.
 *
 * @author Andreas Schamberger <mail@andreass.net>
 * @author Robert Richards <rrichards@cdatazone.org>
 */
abstract class Block extends Key
{
    /**
     * Cipher method.
     *
     * @var string
     */
    protected $cipherMethod;

    /**
     * Key size.
     *
     * @var int
     */
    protected $keySize;

    /**
     * Constructor.
     *
     * @param string $key Key string
     */
    public function __construct($key = null)
    {
        if (!is_null($key)) {
            $givenKeySize = strlen($key);
            if ($givenKeySize != $this->keySize) {
                throw new InvalidArgumentException('key', 'Invalid key size ' . $givenKeySize . ' detected. Expected key size is: ' . $this->keySize);
            }
            $this->key = $key;
        } else {
            $this->key = $this->generateSessionKey();
        }
    }

    /**
     * Decrypt the given data with this key.
     *
     * @param string $data Data to decrypt
     *
     * @return string
     */
    public function decryptData($data)
    {
        $ivLength = openssl_cipher_iv_length($this->cipherMethod);
        $iv = substr($data, 0, $ivLength);
        $data = substr($data, $ivLength);
        // hide warnings with @ operator as we throw exception
        if (false === ($decryptedData = @openssl_decrypt($data, $this->cipherMethod, $this->key, OPENSSL_RAW_DATA, $iv))) {
            // openssl checks PKCS#5 padding in decryption and fails if other padding detected
            // try decryption without padding and try to remove padding by ourselves
            if (version_compare(PHP_VERSION, '5.4.0-dev', '>=')) {
                if (false === ($decryptedData = @openssl_decrypt(base64_encode($data), $this->cipherMethod, $this->key, OPENSSL_ZERO_PADDING, $iv))) {
                    throw new DecryptionException($this->type, $this->getOpenSslErrorString());
                } else {
                    $decryptedData = $this->pkcsUnpad($decryptedData);
                }
            // for PHP 5.3 fall back to mcrypt if available
            } elseif (function_exists('mcrypt_decrypt')) {
                if ($this->cipherMethod == 'des-ede3-cbc') {
                    $mcryptCipherMethod = MCRYPT_TRIPLEDES;
                } else {
                    $mcryptCipherMethod = MCRYPT_RIJNDAEL_128;
                }
                $decryptedData = mcrypt_decrypt($mcryptCipherMethod, $this->key, $data, MCRYPT_MODE_CBC, $iv);
                $decryptedData = $this->pkcsUnpad($decryptedData);
            } else {
                throw new DecryptionException($this->type, $this->getOpenSslErrorString());
            }
        }

        return $decryptedData;
    }

    /**
     * Remove PKCS padding and only check last byte for padding length.
     *
     * adapted from
     * http://us3.php.net/manual/en/function.mcrypt-encrypt.php#102428
     *
     * @param string $string String where PKCS padding should be removed
     *
     * @return string
     */
    protected function pkcsUnpad($string)
    {
        $pad = ord(substr($string, -1));

        return substr($string, 0, -1 * $pad);
    }

    /**
     * Encrypt the given data with this key.
     *
     * @param string $data Data to encrypt
     *
     * @return string
     */
    public function encryptData($data)
    {
        $ivLength = openssl_cipher_iv_length($this->cipherMethod);
        $iv = openssl_random_pseudo_bytes($ivLength);
        // hide warnings with @ operator as we throw exception
        if (false === ($encryptedData = @openssl_encrypt($data, $this->cipherMethod, $this->key, OPENSSL_RAW_DATA, $iv))) {
            throw new EncryptionException($this->type, $this->getOpenSslErrorString());
        }

        return $iv . $encryptedData;
    }

    /**
     * Gets the last error messages from the openSSL library.
     *
     * @return string
     */
    protected function getOpenSslErrorString()
    {
        $errorStrings = array();
        while (false !== ($errorString = openssl_error_string())) {
            $errorStrings[] = $errorString;
        }

        return implode("<br />\n", $errorStrings);
    }

    /**
     * Generates a new session key for this class.
     *
     * @return string
     */
    protected function generateSessionKey()
    {
        return openssl_random_pseudo_bytes($this->keySize);
    }

    /**
     * Sign the given data with this key.
     *
     * @param string $data Data to sign
     *
     * @return string
     */
    public function signData($data)
    {
        return null;
    }

    /**
     * Verifies the given data with this key.
     *
     * @param string $data      Data which should be signed by signature
     * @param string $signature Signature
     *
     * @return boolean
     */
    public function verifySignature($data, $signature)
    {
        return false;
    }
}
