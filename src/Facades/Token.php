<?php

declare(strict_types=1);

namespace DennisCuijpers\SignedToken\Facades;

use DennisCuijpers\SignedToken\SignedToken;
use Illuminate\Support\Facades\Facade;

/**
 * @method static string encode(string $data, ?int $ttl = null)
 * @method static string decode(string $token): string
 * @method static string sign(string $data, ?int $ttl = null)
 * @method static bool verify(string $token, string $data)
 * @method static string uuid()
 * @method static string hex(int $length = 32)
 * @method static string random(int $length = 32)
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
