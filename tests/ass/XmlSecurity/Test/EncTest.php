<?php

namespace ass\XmlSecurity\Tests;

use DOMDocument;

use ass\XmlSecurity\DSig;
use ass\XmlSecurity\Key;
use ass\XmlSecurity\Enc;

class EncTest extends \PHPUnit_Framework_TestCase
{
    protected $fixturesDir;

    protected function setUp()
    {
        $this->fixturesDir = __DIR__ . "/Fixtures";
    }

    /**
     * CipherValue is always different for each encryption and therefore we
     * can't compare the output XML by itself and we need to remove the values.
     *
     * @param string $xml XML document
     *
     * @return string
     */
    protected function removeCipherValues($xml)
    {
        return preg_replace('#<xenc:CipherValue>(.*?)</xenc:CipherValue>#', '<xenc:CipherValue></xenc:CipherValue>', $xml);
    }

    public function testDecryption()
    {
        $key = Key::factory(Key::RSA_OAEP_MGF1P, $this->fixturesDir.'/privkey.pem', true, Key::TYPE_PRIVATE);

        $tests = array(
            array(
                'ref'  => false,
                'file' => 'encrypt_document_element.xml',
                'desc' => 'Decrypt document with type ELEMENT',
            ),
            array(
                'ref'  => false,
                'file' => 'encrypt_document_content.xml',
                'desc' => 'Decrypt document with type CONTENT',
            ),
            array(
                'ref'  => true,
                'file' => 'encrypt_document_element_reference.xml',
                'desc' => 'Encrypt document with type ELEMENT and key reference',
            ),
            array(
                'ref'  => true,
                'file' => 'encrypt_document_content_reference.xml',
                'desc' => 'Encrypt document with type CONTENT and key reference',
            ),
        );

        foreach ($tests as $test) {
            $doc = new DOMDocument();
            $doc->load($this->fixturesDir.'/Enc/'.$test['file']);

            // get a list of encrypted nodes
            $encryptedNodes = Enc::locateEncryptedData($doc);
            // decrypt them
            foreach ($encryptedNodes as $encryptedNode) {
                $decryptionKey = Enc::getSecurityKey($encryptedNode, $key);
                Enc::decryptNode($encryptedNode, $decryptionKey);
            }
            // remove EncryptedKey if still part of XML (CONTENT with referenced key)
            $encryptedKey = Enc::locateEncryptedKey($doc);
            if (null !== $encryptedKey) {
                $encryptedKey->parentNode->removeChild($encryptedKey);
            }

            $file = $this->fixturesDir.'/Enc/encrypt_document.xml';
            $this->assertXmlStringEqualsXmlFile($file, $doc->saveXML(), $test['desc']);
        }
    }

    public function testEncryption()
    {
        $key = Key::factory(Key::AES256_CBC);
        $cert = Key::factory(Key::RSA_OAEP_MGF1P, $this->fixturesDir.'/mycert.pem', true, Key::TYPE_PUBLIC);

        $tests = array(
            array(
                'ref'  => false,
                'type' => Enc::ELEMENT,
                'file' => 'encrypt_document_element.xml',
                'desc' => 'Encrypt document with type ELEMENT',
            ),
            array(
                'ref'  => false,
                'type' => Enc::CONTENT,
                'file' => 'encrypt_document_content.xml',
                'desc' => 'Encrypt document with type CONTENT',
            ),
            array(
                'ref'  => true,
                'type' => Enc::ELEMENT,
                'file' => 'encrypt_document_element_reference.xml',
                'desc' => 'Encrypt document with type ELEMENT and key reference',
            ),
            array(
                'ref'  => true,
                'type' => Enc::CONTENT,
                'file' => 'encrypt_document_content_reference.xml',
                'desc' => 'Encrypt document with type CONTENT and key reference',
            ),
        );

        foreach ($tests as $test) {
            $doc = new DOMDocument();
            $doc->load($this->fixturesDir.'/Enc/encrypt_document.xml');

            if ($test['ref']) {
                $guid = 'EncKey-57cf0489-02e2-45c0-9fcc-fe1a51b53ab2'; // static - normally use DSig::generateUUID()
                $keyInfo = Enc::createEncryptedKeyReferenceKeyInfo($doc, $guid);
                $encryptedData = Enc::encryptNode($doc->documentElement, $test['type'], $key, null, $keyInfo);
                Enc::createEncryptedKey($guid, $key, $cert, $doc->documentElement);
            } else {
                $encryptedData = Enc::encryptNode($doc->documentElement, $test['type'], $key);
                Enc::createEncryptedKey(null, $key, $cert, $encryptedData);
            }

            $file = $this->fixturesDir.'/Enc/'.$test['file'];
            $expected = $this->removeCipherValues(file_get_contents($file));
            $actual = $this->removeCipherValues($doc->saveXML());
            $this->assertEquals($expected, $actual, $test['desc']);
        }
    }
}