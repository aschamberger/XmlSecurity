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

namespace ass\XmlSecurity;

use ass\XmlSecurity\Exception\InvalidArgumentException;

use ass\XmlSecurity\Key\TripleDesCbc;
use ass\XmlSecurity\Key\Aes128Cbc;
use ass\XmlSecurity\Key\Aes192Cbc;
use ass\XmlSecurity\Key\Aes256Cbc;
use ass\XmlSecurity\Key\Rsa15;
use ass\XmlSecurity\Key\RsaOaepMgf1p;
use ass\XmlSecurity\Key\RsaSha1;
use ass\XmlSecurity\Key\RsaSha256;
use ass\XmlSecurity\Key\RsaSha384;
use ass\XmlSecurity\Key\RsaSha512;

/**
 * This class holds a security key and provides the necessary encryption,
 * decryption and certificate handling routines.
 *
 * Usage example for \ass\XmlSecurity\Key:
 * <code>
 * $xmlSecurityKey = new \ass\XmlSecurity\KeyRsaSha1(\ass\XmlSecurity\Key::TYPE_PUBLIC, 'public.pem', true, true);
 * $certificateInOneLine = $xmlSecurityKey->getX509Certificate(true);
 * $thumbprint = $xmlSecurityKey->getX509Thumbprint();
 * $signature = $xmlSecurityKey->sign('data');
 * </code>
 *
 * @author Andreas Schamberger <mail@andreass.net>
 * @author Robert Richards <rrichards@cdatazone.org>
 */
abstract class Key
{
    /**
     * Key type private.
     */
    const TYPE_PRIVATE = 'private';

    /**
     * Key type public
     */
    const TYPE_PUBLIC = 'public';

    /**
     * Block Encryption algorithm TRIPLEDES
     */
    const TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';

    /**
     * Block Encryption algorithm AES-128
     */
    const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /**
     * Block Encryption algorithm AES-192
     */
    const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';

    /**
     * Block Encryption algorithm AES-256
     */
    const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';

    /**
     * Key Transport algorithm RSA-v1.5
     */
    const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

    /**
     * Key Transport algorithm RSA-OAEP
     */
    const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /**
     * Signature DSAwithSHA1 (DSS)
     */
    const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';

    /**
     * Signature RSAwithSHA1
     */
    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    /**
     * Signature RSAwithSHA256
     */
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    /**
     * Signature RSAwithSHA384
     */
    const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';

    /**
     * Signature RSAwithSHA512
     */
    const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    /**
     * Encryption key.
     *
     * @var string
     */
    protected $key = null;

    /**
     * Encryption type.
     *
     * @var string
     */
    protected $type = 0;

    /**
     * Decrypt the given data with this key.
     *
     * @param string $data Data to decrypt
     *
     * @return string
     */
    abstract public function decryptData($data);

    /**
     * Encrypt the given data with this key.
     *
     * @param string $data Data to encrypt
     *
     * @return string
     */
    abstract public function encryptData($data);

    /**
     * Factory method.
     *
     * @param string  $encryptionType Encryption algorithm
     * @param string  $key            Key string
     * @param boolean $keyIsFile      Key parameter is file name
     * @param string  $keyType        Key::TYPE_PUBLIC | Key::TYPE_PRIVATE
     * @param string  $passphrase     Passphrase for key
     *
     * @return Key
     */
    public static function factory($encryptionType, $key = null, $keyIsFile = true, $keyType = null, $passphrase = null)
    {
        switch ($encryptionType) {
            case self::TRIPLEDES_CBC:
                return new TripleDesCbc($key);
                break;
            case self::AES128_CBC:
                return new Aes128Cbc($key);
                break;
            case self::AES192_CBC:
                return new Aes192Cbc($key);
                break;
            case self::AES256_CBC:
                return new Aes256Cbc($key);
                break;
            case self::RSA_1_5:
                return new Rsa15($keyType, $key, $keyIsFile, $passphrase);
                break;
            case self::RSA_OAEP_MGF1P:
                return new RsaOaepMgf1p($keyType, $key, $keyIsFile, $passphrase);
                break;
            case self::RSA_SHA1:
                return new RsaSha1($keyType, $key, $keyIsFile, $passphrase);
                break;
            case self::RSA_SHA256:
                return new RsaSha256($keyType, $key, $keyIsFile, $passphrase);
                break;
            case self::RSA_SHA384:
                return new RsaSha384($keyType, $key, $keyIsFile, $passphrase);
                break;
            case self::RSA_SHA512:
                return new RsaSha512($keyType, $key, $keyIsFile, $passphrase);
                break;
            default:
                throw new InvalidArgumentException('encryptionType', 'Invalid encryption type given');

                return;
        }
    }

    /**
     * Gets the algorithm for this key.
     *
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->type;
    }

    /**
     * Gets the key this class represents in form of a string.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Sign the given data with this key and return signature.
     *
     * @param string $data Data to sign
     *
     * @return string
     */
    abstract public function signData($data);

    /**
     * Verifies the given data with this key.
     *
     * @param string $data      Data which should be signed by signature
     * @param string $signature Signature string
     *
     * @return boolean
     */
    abstract public function verifySignature($data, $signature);
}
