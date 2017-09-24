<?php

namespace SSHKey\Tests;

use PHPUnit\Framework\TestCase;
use SSHKey\SSHKey;

class SSHKeyTest extends TestCase
{
    public function testReadingTestKey()
    {
        $contents = file_get_contents(__DIR__ . '/testkey');

        $key = SSHKey::fromOpenSshKey($contents);

        $this->assertEquals('ssh-ed25519', $key->getType());
        $this->assertEquals('sometestkey@localhost', $key->getName());
        $secretKey = hex2bin('2e2cbdc58a7d77de1ca848f397387440efbab26951e5d6f34f2a0a0fde80824eb357a4a83503566eb04c91a02764e4fbc72638778b30b164a8355927533cb1be');
        $this->assertEquals($secretKey, $key->getSecretKey());
        $publicKey = hex2bin('b357a4a83503566eb04c91a02764e4fbc72638778b30b164a8355927533cb1be');
        $this->assertEquals($publicKey, $key->getPublicKey());
    }
}