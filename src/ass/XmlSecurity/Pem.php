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

/**
 * This class provides methods to convert between different security key
 * representations.
 *
 * Usage example for \ass\XmlSecurity\Pem:
 * <code>
 * $key = 'key ...';
 * $pem = \ass\XmlSecurity\Pem::formatKeyInPemFormat($key, \ass\XmlSecurity\Pem::PEM_TYPE_CERTIFICATE_X509);
 * $modulus = '';
 * $exponent = '';
 * $pem = \ass\XmlSecurity\Pem::getPublicKeyFromModExp($modulus, $exponent);
 * </code>
 *
 * @author Andreas Schamberger <mail@andreass.net>
 * @author Robert Richards <rrichards@cdatazone.org>
 */
class Pem
{
    /**
     * ASN.1 type INTEGER
     */
    const ASN_TYPE_INTEGER = 0x02;

    /**
     * ASN.1 type BITSTRING
     */
    const ASN_TYPE_BITSTRING = 0x03;

    /**
     * ASN.1 type SEQUENCE
     */
    const ASN_TYPE_SEQUENCE = 0x30;

    /**
     * PEM type PKCS1
     */
    const PEM_TYPE_PRIVATE_PKCS1 = "RSA PRIVATE KEY";

    /**
     * PEM type PKCS8
     */
    const PEM_TYPE_PRIVATE_PKCS8 =  "PRIVATE KEY";

    /**
     * PEM type X.509 certifficate
     */
    const PEM_TYPE_CERTIFICATE_X509 = "CERTIFICATE";

    /**
     * PEM type X.509 public key
     */
    const PEM_TYPE_PUBLIC_X509 = "PUBLIC KEY";

    /**
     * The object identifier for DSA Keys (1.2.840.10040.4.1)
     */
    const OBJECT_IDENTIFIER_DSA = "\x06\x07\x2a\x86\x48\xce\x38\x04\x01";

    /**
     * The object identifier for RSA Keys (1.2.840.113549.1.1.1)
     */
    const OBJECT_IDENTIFIER_RSA = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    /**
     * Encode a subset of data types into ASN.1 encoding format.
     *
     * @param string $type ASN.1 type
     * @param string $data Data to encode
     *
     * @return string
     */
    private static function encodeAsnData($type, $data)
    {
        if (($type === self::ASN_TYPE_INTEGER && ord($data) > 0x7f) || $type === self::ASN_TYPE_BITSTRING) {
            $data = chr(0) . $data;
        }
        $length = strlen($data);
        if ($length < 0x80) {
           $output = sprintf("%c%c%s", $type, $length, $data);
        } elseif ($length < 0x0100) {
           $output = sprintf("%c%c%c%s", $type, 0x81, $length, $data);
        } elseif ($length < 0x010000) {
           $output = sprintf("%c%c%c%c%s", $type, 0x82, $length/0x0100, $length%0x0100, $data);
        } else {
            $output = null;
        }

        return $output;
    }

    /**
     * Formats the given key string (base64 encoded) in desired PEM format.
     *
     * @param string $key  Key to format
     * @param string $type PEM_TYPE_* constant
     *
     * @return string
     */
    public static function formatKeyInPemFormat($key, $type=self::PEM_TYPE_CERTIFICATE_X509)
    {
        $key = str_replace(array("\r", "\n"), '', $key);
        $pem = "-----BEGIN " . $type . "-----\n";
        $pem .= chunk_split($key, 64, "\n");
        $pem .= "-----END " . $type . "-----\n";

        return $pem;
    }

    /**
     * Transform a RSA Key in Modulus/Exponent format into PEM encoding.
     *
     * @param string $modulus  RSA Modulus in binary format
     * @param string $exponent RSA exponent in binary format
     *
     * @return string
     *
     * @see: https://polarssl.org/kb/cryptography/asn1-key-structures-in-der-and-pem
     * @see: http://lapo.it/asn1js/
     */
    public static function getPublicKeyFromModExp($modulus, $exponent)
    {
        // the code is formatted like the logical nodes in the ASN.1 format
        $publicKey = self::encodeAsnData(self::ASN_TYPE_SEQUENCE,
            self::encodeAsnData(self::ASN_TYPE_SEQUENCE,
                self::OBJECT_IDENTIFIER_RSA .
                "\x05\x00"
            ) .
            self::encodeAsnData(self::ASN_TYPE_BITSTRING,
                self::encodeAsnData(self::ASN_TYPE_SEQUENCE,
                    self::encodeAsnData(self::ASN_TYPE_INTEGER, $modulus) .
                    self::encodeAsnData(self::ASN_TYPE_INTEGER, $exponent)
                )
            )
        );
        $publicKeyBase64 = base64_encode($publicKey);

        return self::formatKeyInPemFormat($publicKeyBase64, self::PEM_TYPE_PUBLIC_X509);
    }

    /**
     * Transform a DSA Key in P/Q/G/Y format into PEM encoding.
     *
     * @param string $p P
     * @param string $q Q
     * @param string $g G
     * @param string $y Y
     *
     * @return string
     */
    public static function getPublicKeyFromPqgy($p, $q, $g, $y)
    {
        // the code is formatted like the logical nodes in the ASN.1 format
        $publicKey = self::encodeAsnData(self::ASN_TYPE_SEQUENCE,
            self::encodeAsnData(self::ASN_TYPE_SEQUENCE,
                self::OBJECT_IDENTIFIER_DSA .
                self::encodeAsnData(self::ASN_TYPE_SEQUENCE,
                    self::encodeAsnData(self::ASN_TYPE_INTEGER, $p) .
                    self::encodeAsnData(self::ASN_TYPE_INTEGER, $q) .
                    self::encodeAsnData(self::ASN_TYPE_INTEGER, $g)
                )
            ) .
            self::encodeAsnData(self::ASN_TYPE_BITSTRING,
                self::encodeAsnData(self::ASN_TYPE_INTEGER, $y)
            )
        );
        $publicKeyBase64 = base64_encode($publicKey);

        return self::formatKeyInPemFormat($publicKeyBase64, self::PEM_TYPE_PUBLIC_X509);
    }

    /**
     * Parses a PEM file and returns the keys of the desired type in it.
     *
     * Can detect multiple certificates and returns an array of them.
     * If no boundary is found it is assumed there is a single key given.
     * The key is returned in a single line without breaks.
     *
     * @param string $pem  PEM to parse
     * @param string $type PEM_TYPE_* constant
     *
     * @return string|array(string)
     */
    public static function parseKeyFromPemFormat($pem, $type=self::PEM_TYPE_CERTIFICATE_X509)
    {
        if (strpos($pem, '-----BEGIN') !== false) {
            $beginBoundary = '-----BEGIN ' . $type . '-----';
            $endBoundary = '-----END ' . $type . '-----';
            $data = '';
            $lines = explode("\n", $pem);
            $inData = false;
            $keys = array();
            foreach ($lines as $line) {
                $line = trim($line);
                if ($inData === false) {
                    if ($line == $beginBoundary) {
                        $inData = true;
                    }
                } else {
                    if ($line == $endBoundary) {
                        $inData = false;
                        $keys[] = $data;
                        $data = '';
                    } else {
                        $data .= $line;
                    }
                }
            }
            if ($type == self::PEM_TYPE_CERTIFICATE_X509) {
                return $keys;
            } else {
                return array_pop($keys);
            }
        } else {
            return str_replace(array("\r", "\n"), '', $pem);
        }
    }
}
