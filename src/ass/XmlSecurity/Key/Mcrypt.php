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

use ass\XmlSecurity\Exception\InvalidArgumentException;

/**
 * This class holds a security key and provides the necessary encryption,
 * decryption and certificate handling routines.
 *
 * @author Andreas Schamberger <mail@andreass.net>
 * @author Robert Richards <rrichards@cdatazone.org>
 */
abstract class Mcrypt extends \ass\XmlSecurity\Key
{
    /**
     * Mcrypt cipher type.
     *
     * @var string
     */
    protected $cipher = MCRYPT_RIJNDAEL_128;

    /**
     * Mcrypt initialization vector (IV) from a random source.
     *
     * @var string
     */
    protected $iv = null;

    /**
     * Mcrypt mode.
     */
    protected $mode = MCRYPT_MODE_CBC;

    /**
     * Constructor.
     *
     * @param string $key Key string
     */
    public function __construct($key = null)
    {
        if (!is_null($key)) {
            $givenKeySize = strlen($key);
            $keySize = $this->getAlgorithmKeySize();
            if ($givenKeySize != $keySize) {
                throw new InvalidArgumentException('key', 'Invalid key size ' . $givenKeySize . ' detected. Expected key size is: ' . $keySize);
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
        if (false === ($td = mcrypt_module_open($this->cipher, '', $this->mode, ''))) {
            throw new DecryptionException($this->type, 'Could not create mcrypt encryption descriptor.');
        }
        $ivLength = mcrypt_enc_get_iv_size($td);
        $this->iv = substr($data, 0, $ivLength);
        $data = substr($data, $ivLength);
        // hide mcrypt warning with @ operator as we throw exception
        if (0 !== ($errorCode = @mcrypt_generic_init($td, $this->key, $this->iv))) {
            throw new DecryptionException($this->type, $this->getMcryptErrorString($errorCode));
        }
        $decryptedData = mdecrypt_generic($td, $data);
        if ($this->mode === MCRYPT_MODE_CBC) {
            $decryptedData = $this->pkcsUnpad($decryptedData);
        }
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $decryptedData;
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
        if (false === ($td = mcrypt_module_open($this->cipher, '', $this->mode, ''))) {
            throw new EncryptionException($this->type, 'Could not create mcrypt encryption descriptor.');
        }
        $ivLength = mcrypt_enc_get_iv_size($td);
        $this->iv = mcrypt_create_iv($ivLength, MCRYPT_RAND);
        // hide mcrypt warning with @ operator as we throw exception
        if (0 !== ($errorCode = @mcrypt_generic_init($td, $this->key, $this->iv))) {
            throw new EncryptionException($this->type, $this->getMcryptErrorString($errorCode));
        }
        if ($this->mode === MCRYPT_MODE_CBC) {
            $blocksize = mcrypt_enc_get_block_size($td);
            $data = $this->pkcsPad($data, $blocksize);
        }
        $encryptedData = $this->iv . mcrypt_generic($td, $data);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $encryptedData;
    }

    /**
     * Determines the key size of the algorithm.
     *
     * @return int
     */
    protected function getAlgorithmKeySize()
    {
        $keySize = mcrypt_module_get_algo_key_size($this->cipher);
        if ($this->cipher == MCRYPT_RIJNDAEL_128) {
            if ($this->type == self::AES192_CBC) {
                $keySize = 24;
            } elseif ($this->type == self::AES128_CBC) {
                $keySize = 16;
            }
        }

        return $keySize;
    }

    /**
     * Convert mcrypt error codes from function mcrypt_generic_init() into
     * error messages.
     *
     * @param mixed $errorCode Error code returned from mcrypt_generic_init()
     *
     * @return string
     */
    protected function getMcryptErrorString($errorCode)
    {
        /*
         * mcrypt_generic_init() returns a negative value on error, -3 when the
         * key length was incorrect, -4 when there was a memory allocation
         * problem and any other return value is an unknown error. If an error
         * occurs a warning will be displayed accordingly. false is returned if
         * incorrect parameters were passed.
         */
        if (false === $errorCode) {
            return 'Incorrect parameters passed to mcrypt_generic_init()!';
        } elseif (-3 === $errorCode) {
            return 'Invalid key length for key passed to mcrypt_generic_init()!';
        } elseif (-4 === $errorCode) {
            return 'Memory allocation problem with mcrypt!';
        } else {
            return 'Unkown mcrypt error occured!';
        }
    }

    /**
     * Generates a new session key for this class.
     *
     * @return string
     */
    protected function generateSessionKey()
    {
        $keySize = $this->getAlgorithmKeySize();

        return mcrypt_create_iv($keySize, MCRYPT_RAND);
    }

    /**
     * Add PKCS padding
     *
     * http://us3.php.net/manual/en/function.mcrypt-encrypt.php#102428
     *
     * @param string $string    String where PKCS padding should be added
     * @param int    $blocksize PKCS blocksize
     *
     * @return string
     */
    protected function pkcsPad ($string, $blocksize)
    {
        $pad = $blocksize - (strlen($string) % $blocksize);

        return $string . str_repeat(chr($pad), $pad);
    }

    /**
     * Remove PKCS padding
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
