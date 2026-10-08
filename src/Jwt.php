<?php

namespace dilmurodzk\jwt;

use DateTimeImmutable;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Throwable;
use yii\base\Component;
use yii\base\InvalidConfigException;

/**
 * JWT component.
 *
 * Config example:
 * ```php
 * 'jwt' => [
 *     'class' => \dilmurodzk\jwt\Jwt::class,
 *     'key' => 'secret-key-at-least-32-characters-long',
 *     'jwtId' => 'unique-id',
 *     'expire' => '1440 minute',
 * ],
 * ```
 *
 * Usage:
 * ```php
 * $token = Yii::$app->jwt->build(['claims' => ['uid' => $user->id]]);
 * $string = $token->toString();
 *
 * $token = Yii::$app->jwt->load($string); // UnencryptedToken|null
 * ```
 */
class Jwt extends Component
{
    /**
     * @var string HMAC SHA-256 secret key (min. 32 characters).
     */
    public string $key = '';

    /**
     * @var string|null value of the "jti" claim. Checked on load when set.
     */
    public ?string $jwtId = null;

    /**
     * @var string token lifetime in DateTime::modify() format, e.g. "3 hours", "1440 minute".
     */
    public string $expire = '1 hour';

    /**
     * @var string|null value of the "iss" claim.
     */
    public ?string $issuer = null;

    /**
     * @var string|null value of the "aud" claim.
     */
    public ?string $audience = null;

    private ?Configuration $_configuration = null;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();
        if (strlen($this->key) < 32) {
            throw new InvalidConfigException('Jwt::$key must be at least 32 characters long.');
        }
    }

    public function getConfiguration(): Configuration
    {
        if ($this->_configuration === null) {
            $this->_configuration = Configuration::forSymmetricSigner(
                new Sha256(),
                InMemory::plainText($this->key)
            );
            $constraints = [new SignedWith($this->_configuration->signer(), $this->_configuration->verificationKey())];
            $constraints[] = new LooseValidAt(SystemClock::fromSystemTimezone());
            if ($this->jwtId !== null) {
                $constraints[] = new IdentifiedBy($this->jwtId);
            }
            $this->_configuration->setValidationConstraints(...$constraints);
        }
        return $this->_configuration;
    }

    /**
     * Creates a signed token.
     *
     * @param array $options supported keys:
     * - claims: array custom claims, e.g. ['uid' => 1]
     * - expire: string overrides [[expire]]
     */
    public function build(array $options = []): UnencryptedToken
    {
        $config = $this->getConfiguration();
        $now = new DateTimeImmutable();
        $expire = $options['expire'] ?? $this->expire;

        $builder = $config->builder()
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify('+' . ltrim($expire, '+')));

        if ($this->jwtId !== null) {
            $builder = $builder->identifiedBy($this->jwtId);
        }
        if ($this->issuer !== null) {
            $builder = $builder->issuedBy($this->issuer);
        }
        if ($this->audience !== null) {
            $builder = $builder->permittedFor($this->audience);
        }
        foreach ($options['claims'] ?? [] as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken($config->signer(), $config->signingKey());
    }

    /**
     * Parses a token string. Returns null if it is malformed or, when $validate is true, invalid.
     */
    public function load(string $token, bool $validate = true): ?UnencryptedToken
    {
        try {
            $parsed = $this->getConfiguration()->parser()->parse($token);
        } catch (Throwable $e) {
            return null;
        }
        if (!$parsed instanceof UnencryptedToken) {
            return null;
        }
        if ($validate && !$this->validate($parsed)) {
            return null;
        }
        return $parsed;
    }

    /**
     * Checks signature, expiration and configured claims.
     */
    public function validate(Token $token): bool
    {
        $config = $this->getConfiguration();
        return $config->validator()->validate($token, ...$config->validationConstraints());
    }
}
