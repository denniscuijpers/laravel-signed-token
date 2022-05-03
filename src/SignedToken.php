<?php

declare(strict_types=1);

namespace DennisCuijpers\SignedToken;

use Carbon\Carbon;
use DennisCuijpers\SignedToken\Exceptions\TokenExpiredException;
use DennisCuijpers\SignedToken\Exceptions\TokenInvalidException;

class SignedToken
{
    private const ALPHABET  = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const SEPARATOR = 'Z';
    private const TO_BASE   = 61;

    public function __construct(private array $config)
    {
    }

    public function encode(string $data, int $ttl = 0): string
    {
        return $this->encodeRaw($this->baseEncode($data), $ttl);
    }

    public function decode(string $token): string
    {
        return $this->baseDecode($this->decodeRaw($token));
    }

    public function sign(string $data, ?int $ttl = null): string
    {
        return $this->encodeRaw($this->signature($data), $ttl);
    }

    public function verify(string $token, string $data): bool
    {
        return hash_equals($this->signature($data), $this->decodeRaw($token));
    }

    public function uuid(): string
    {
        $data = random_bytes(16);

        $data[6] = chr(ord($data[6]) & 0x0F | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3F | 0x80); // set bits 6-7 to 10

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    public function isUuid(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $uuid) > 0;
    }

    public function number(int $length = 9): string
    {
        $number = mt_rand(1, 9);

        for ($i = 1; $i < $length; $i++) {
            $number .= mt_rand(0, 9);
        }

        return $number;
    }

    public function isNumber(string $number, int $length = 9): bool
    {
        return preg_match('/^[0-9]{' . $length . '}$/', $number) > 0;
    }

    public function hex(int $length = 32): string
    {
        $random = random_bytes((int) ceil($length / 2));

        return substr(bin2hex($random), 0, $length);
    }

    public function isHex(string $hex, int $length = 32): bool
    {
        return preg_match('/^[0-9a-f]{' . $length . '}$/', $hex) > 0;
    }

    public function random(int $length = 32): string
    {
        $random = random_bytes($length);

        return substr($this->baseEncode($random), 0, $length);
    }

    public function isRandom(string $random, int $length = 32): bool
    {
        return preg_match('/^[0-9a-zA-Z]{' . $length . '}$/', $random) > 0;
    }

    private function encodeRaw(string $data, int $ttl = 0): string
    {
        $payload = implode(static::SEPARATOR, [
            $data,
            $this->baseEncodeInt($this->now()),
            $this->baseEncodeInt($ttl),
        ]);

        return $payload . static::SEPARATOR . $this->signature($payload);
    }

    private function decodeRaw(string $token): string
    {
        if (substr_count($token, static::SEPARATOR) !== 3) {
            throw new TokenInvalidException('Invalid token content');
        }

        [$data, $timestamp, $ttl, $signature] = explode(static::SEPARATOR, $token);

        $payload = implode(static::SEPARATOR, [$data, $timestamp, $ttl]);

        if ($this->signature($payload) !== $signature) {
            throw new TokenInvalidException('Invalid token signature');
        }

        $timestamp = $this->baseDecodeInt($timestamp);
        $ttl       = $this->baseDecodeInt($ttl);

        if ($ttl !== 0 && $timestamp + $ttl < $this->now()) {
            throw new TokenExpiredException('Expired token');
        }

        return $data;
    }

    private function signature(string $data): string
    {
        $hash = hash_hmac($this->config['algo'], $data, $this->config['key'], true);

        return substr($this->baseEncode($hash), 0, $length ?? $this->config['length']);
    }

    private function baseEncode(string $data): string
    {
        $data = array_map(fn ($char) => ord($char), str_split($data));

        $data = $this->baseConvert($data, 256, static::TO_BASE);

        return implode('', array_map(fn ($index) => static::ALPHABET[$index], $data));
    }

    private function baseEncodeInt(int $data): string
    {
        $data = $this->baseConvert([$data], 256, static::TO_BASE);

        return implode('', array_map(fn ($index) => static::ALPHABET[$index], $data));
    }

    private function baseDecode(string $data): string
    {
        $data = array_map(fn ($char) => strpos(static::ALPHABET, $char), str_split($data));

        $data = $this->baseConvert($data, static::TO_BASE, 256);

        return implode('', array_map(fn ($char) => chr($char), $data));
    }

    private function baseDecodeInt(string $data): int
    {
        $data = array_map(fn ($char) => strpos(static::ALPHABET, $char), str_split($data));

        $data = $this->baseConvert($data, static::TO_BASE, 10);

        return (int) implode('', $data);
    }

    private function baseConvert(array $data, int $from, int $to): array
    {
        $result = [];
        while ($count = count($data)) {
            $quotient  = [];
            $remainder = 0;
            for ($i = 0; $i < $count; $i++) {
                $accumulator = $data[$i] + $remainder * $from;
                $digit       = intdiv($accumulator, $to);
                $remainder   = $accumulator % $to;
                if (count($quotient) || $digit) {
                    $quotient[] = $digit;
                }
            }
            array_unshift($result, $remainder);
            $data = $quotient;
        }

        return $result;
    }

    private function now(): int
    {
        return Carbon::now()->unix();
    }
}
