<?php

namespace dilmurodzk\jwt;

use yii\di\Instance;
use yii\filters\auth\HttpBearerAuth;

/**
 * Authenticates requests by "Authorization: Bearer <jwt>" header.
 *
 * The parsed token (Lcobucci\JWT\UnencryptedToken) is passed to
 * IdentityInterface::findIdentityByAccessToken($token, $type).
 */
class JwtHttpBearerAuth extends HttpBearerAuth
{
    /**
     * @var Jwt|string|array the Jwt component or its application component ID.
     */
    public $jwt = 'jwt';

    public function init(): void
    {
        parent::init();
        $this->jwt = Instance::ensure($this->jwt, Jwt::class);
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate($user, $request, $response)
    {
        $authHeader = $request->getHeaders()->get($this->header);
        if ($authHeader === null || !preg_match($this->pattern, $authHeader, $matches)) {
            return null;
        }

        $token = $this->jwt->load($matches[1]);
        if ($token === null) {
            $this->handleFailure($response);
        }

        $identity = $user->loginByAccessToken($token, get_class($this));
        if ($identity === null) {
            $this->handleFailure($response);
        }

        return $identity;
    }
}
