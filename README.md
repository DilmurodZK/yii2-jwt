# yii2-jwt

JWT component and HTTP Bearer auth filter for Yii2, built on [lcobucci/jwt](https://github.com/lcobucci/jwt) (HS256).

## Installation

```json
"repositories": [
  { "type": "vcs", "url": "https://github.com/DilmurodZK/yii2-jwt" }
],
"require": {
  "dilmurodzk/yii2-jwt": "dev-main"
}
```

## Configuration

```php
'components' => [
    'jwt' => [
        'class' => \dilmurodzk\jwt\Jwt::class,
        'key' => 'secret-key-at-least-32-characters-long',
        'jwtId' => 'unique-id',      // optional, "jti" claim
        'expire' => '1440 minute',   // DateTime::modify() format
        // 'issuer' => '...',        // optional, "iss" claim
        // 'audience' => '...',      // optional, "aud" claim
    ],
],
```

## Usage

Create a token:

```php
$token = Yii::$app->jwt->build(['claims' => ['uid' => $user->id]]);
echo $token->toString();
```

Protect a controller:

```php
public function behaviors()
{
    $behaviors = parent::behaviors();
    $behaviors['authenticator'] = [
        'class' => \dilmurodzk\jwt\JwtHttpBearerAuth::class,
    ];
    return $behaviors;
}
```

The identity class receives the parsed token:

```php
public static function findIdentityByAccessToken($token, $type = null)
{
    return static::findOne(['id' => $token->claims()->get('uid')]);
}
```
