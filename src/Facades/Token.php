<?php

declare(strict_types=1);

namespace DennisCuijpers\SignedToken\Facades;

use DennisCuijpers\SignedToken\SignedToken;
use Illuminate\Support\Facades\Facade;

/**
 * @method static string make($data, ?int $ttl = null)
 * @method static string sign(string $data, int $length = null)
 * @method static string random(int $length = null)
 * @method static get(string $token, $default = null)
 * @method static int|null ttl(string $token)
 *
 * @see SignedToken
 */
class Token extends Facade
{
    public static function getFacadeAccessor(): string
    {
        return 'signed_token';
    }
}
