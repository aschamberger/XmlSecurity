<?php

namespace ass\XmlSecurity\Tests;

use DOMDocument;

use ass\XmlSecurity\DSig;
use ass\XmlSecurity\Key;

class DSigTest extends \PHPUnit_Framework_TestCase
{
    protected $fixturesDir;

    protected function setUp()
    {
        $this->fixturesDir = __DIR__ . "/Fixtures";
    }

    public function testVerifyWithCommentEmptyUri()
    {
        $doc = new DOMDocument();
        $doc->load($this->fixturesDir.'/DSig/withcomment_empty_uri.xml');

        $signature = DSig::locateSignature($doc);

        $this->assertInstanceOf('\DOMElement', $signature, 'Signature element');

        $this->assertTrue(DSig::verifyReferences($signature), 'Verify references');
        $this->assertTrue(DSig::verifyDocumentSignature($signature), 'Verify signature');
    }

    public function testVerifyWithCommentIdUri()
    {
        $doc = new DOMDocument();
        $doc->load($this->fixturesDir.'/DSig/withcomment_id_uri.xml');

        $signature = DSig::locateSignature($doc);

        $this->assertInstanceOf('\DOMElement', $signature, 'Signature element');

        $options = array(
            'id_name'      => 'id',
            'id_ns_prefix' => 'xml',
            'id_prefix_ns' => 'http://www.w3.org/XML/1998/namespace',
        );
        $this->assertTrue(DSig::verifyReferences($signature, $options), 'Verify references');
        $this->assertTrue(DSig::verifyDocumentSignature($signature), 'Verify signature');
    }

    public function testVerifyDocumentSha1()
    {
        $doc = new DOMDocument();
        $doc->load($this->fixturesDir.'/DSig/sign_document_sha1_result.xml');

        $signature = DSig::locateSignature($doc);

        $this->assertInstanceOf('\DOMElement', $signature, 'Signature element');

        $this->assertTrue(DSig::verifyReferences($signature), 'Verify references');
        $this->assertTrue(DSig::verifyDocumentSignature($signature), 'Verify signature');
    }

    public function testVerifyDocumentSha256()
    {
        $doc = new DOMDocument();
        $doc->load($this->fixturesDir.'/DSig/sign_document_sha256_result.xml');

        $signature = DSig::locateSignature($doc);

        $this->assertInstanceOf('\DOMElement', $signature, 'Signature element');

        $this->assertTrue(DSig::verifyReferences($signature), 'Verify references');
        $this->assertTrue(DSig::verifyDocumentSignature($signature), 'Verify signature');
    }

    public function testSignDocumentSha1()
    {
        // if key has a passphrase, set it via fifth parameter in factory
        $key = Key::factory(Key::RSA_SHA1, $this->fixturesDir.'/privkey.pem', true, Key::TYPE_PRIVATE);
        $cert = Key::factory(Key::RSA_SHA1, $this->fixturesDir.'/mycert.pem', true, Key::TYPE_PUBLIC);

        $doc = new DOMDocument();
        $doc->formatOutput = true;
        $doc->load($this->fixturesDir.'/DSig/sign_document.xml');

        $keyInfo = DSig::createX509CertificateKeyInfo($doc, $cert);

        $signature = DSig::createSignature($key, DSig::EXC_C14N, $doc->documentElement, null, $keyInfo);
        DSig::addNodeToSignature($signature, $doc, DSig::SHA1, DSig::TRANSFORMATION_ENVELOPED_SIGNATURE);
        DSig::signDocument($signature, $key, DSig::EXC_C14N);

        $file = $this->fixturesDir.'/DSig/sign_document_sha1_result.xml';
        $this->assertXmlStringEqualsXmlFile($file, $doc->saveXML(), "Sign document with SHA1");
    }

    public function testSignDocumentSha256()
    {
        // if key has a passphrase, set it via fifth parameter in factory
        $key = Key::factory(Key::RSA_SHA256, $this->fixturesDir.'/privkey.pem', true, Key::TYPE_PRIVATE);
        $cert = Key::factory(Key::RSA_SHA256, $this->fixturesDir.'/mycert.pem', true, Key::TYPE_PUBLIC);

        $doc = new DOMDocument();
        $doc->formatOutput = true;
        $doc->load($this->fixturesDir.'/DSig/sign_document.xml');

        $keyInfo = DSig::createX509CertificateKeyInfo($doc, $cert);

        $signature = DSig::createSignature($key, DSig::EXC_C14N, $doc->documentElement, null, $keyInfo);
        DSig::addNodeToSignature($signature, $doc, DSig::SHA1, DSig::TRANSFORMATION_ENVELOPED_SIGNATURE);
        DSig::signDocument($signature, $key, DSig::EXC_C14N);

        $file = $this->fixturesDir.'/DSig/sign_document_sha256_result.xml';
        $this->assertXmlStringEqualsXmlFile($file, $doc->saveXML(), "Sign document with SHA256");
    }
}