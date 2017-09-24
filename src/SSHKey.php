<?php

namespace SSHKey;

class SSHKey
{
    const MARK_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    const MARK_END   = "-----END OPENSSH PRIVATE KEY-----\n";

    const AUTH_MAGIC = "openssh-key-v1";

    private $sk;
    private $pk;
    private $type;
    private $name;

    public function __construct(string $pk, string $sk, string $type, string $name)
    {
        $this->sk   = $sk;
        $this->pk   = $pk;
        $this->type = $type;
        $this->name = $name;
    }

    private static function getSshPrivateKeyBin(string $openSshKey)
    {
        $parts = explode(static::MARK_BEGIN, $openSshKey);
        if (count($parts) === 1) {
            throw new \InvalidArgumentException('Could not locate ssh key');
        }

        $parts = explode(static::MARK_END, $parts[1]);
        if (count($parts) === 1) {
            throw new \InvalidArgumentException('No end mark found in key string');
        }

        $encodedKey = $parts[0];

        $rawKey = base64_decode($encodedKey);
        if ($rawKey === false) {
            throw new \InvalidArgumentException('Invalid base64 data');
        }

        return $rawKey;
    }

    private static function getInt(string $binBuffer)
    {
        if (strlen($binBuffer) < 4) {
            throw new \InvalidArgumentException('Tried to get string len when there is not enough data to get the length');
        }

        return [unpack("N", $binBuffer)[1], substr($binBuffer, 4)];
    }

    private static function sshBufGetString(string $binBuffer)
    {
        [$size, $binBuffer] = static::getInt($binBuffer);

        return [substr($binBuffer, 0, $size), substr($binBuffer, $size)];
    }

    private static function deserializePrivateKey(string $buffer)
    {
        [$type, $buffer] = self::sshBufGetString($buffer);
        if ($type !== 'ssh-ed25519') {
            throw new \Exception('Unsupported key type');
        }

        [$pk, $buffer] = self::sshBufGetString($buffer);
        [$sk, $buffer] = self::sshBufGetString($buffer);
        [$keyName, $buffer] = self::sshBufGetString($buffer);

        return [
            'type' => $type,
            'pk'   => $pk,
            'sk'   => $sk,
            'name' => $keyName
        ];
    }

    private static function parseBinKey(string $binKey)
    {
        if (strncmp(static::AUTH_MAGIC, $binKey, strlen(static::AUTH_MAGIC))) {
            throw new \InvalidArgumentException('Key magic not found');
        }

        $binKey = substr($binKey, strlen(static::AUTH_MAGIC) + 1);

        [$cipherName, $binKey] = static::sshBufGetString($binKey);
        [$kdfName, $binKey] = static::sshBufGetString($binKey);
        [$kdf, $binKey] = static::sshBufGetString($binKey);
        [$nkeys, $binKey] = static::getInt($binKey);
        [$pubKey, $binKey] = static::sshBufGetString($binKey);
        [$keyData, $binKey] = static::sshBufGetString($binKey);

        // TODO: implement bcrypt for encrypted private key
        if ($cipherName !== 'none' || $kdfName !== 'none') {
            throw new \Exception('Encrypted keys not supported');
        }

        [$check1, $keyData] = static::getInt($keyData);
        [$check2, $keyData] = static::getInt($keyData);

        if ($check1 !== $check2) {
            throw new \InvalidArgumentException('Invalid private key');
        }

        $privateKey = static::deserializePrivateKey($keyData);

        return $privateKey;
    }

    // ref: https://github.com/openssh/openssh-portable/blob/master/sshkey.c
    public static function fromOpenSshKey(string $openSshKey, string $password = null)
    {
        $rawKey = static::getSshPrivateKeyBin($openSshKey);

        $key = static::parseBinKey($rawKey);

        return new static($key['pk'], $key['sk'], $key['type'], $key['name']);
    }

    public function getSecretKey(): string
    {
        return $this->sk;
    }

    public function getPublicKey(): string
    {
        return $this->pk;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getName(): string
    {
        return $this->name;
    }
}
