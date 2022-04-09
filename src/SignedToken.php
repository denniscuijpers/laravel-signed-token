<?php

declare(strict_types=1);

namespace DennisCuijpers\SignedToken;

class SignedToken
{
    private const ALPHABET  = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const SEPARATOR = 'Z';
    private const TO_BASE   = 61;

    public function __construct(private array $config)
    {
    }

    public function make($data, ?int $ttl = null): string
    {
        $payload = $this->encode($this->serialize([
            $data,
            $ttl !== null ? $this->now() + $ttl : null,
        ]));

        return $payload . static::SEPARATOR . $this->sign($payload);
    }

    public function sign(string $data, int $length = null): string
    {
        $hash = hash_hmac($this->config['algo'], $data, $this->config['key'], true);

        return substr($this->encode($hash), 0, $length ?? $this->config['length']);
    }

    public function random(int $length = null): string
    {
        $random = random_bytes($length ?? $this->config['length']);

        return substr($this->encode($random), 0, $length ?? $this->config['length']);
    }

    public function get(string $token, $default = null)
    {
        if (!$parsed = $this->parse($token)) {
            return $default;
        }

        [$data, $expires] = $parsed;

        if ($expires !== null && $expires < $this->now()) {
            return null;
        }

        return $data;
    }

    public function ttl(string $token): ?int
    {
        if (!$parsed = $this->parse($token)) {
            return null;
        }

        [$data, $expires] = $parsed;

        if ($expires === null) {
            return null;
        }

        return $expires - $this->now();
    }

    private function parse(string $token): ?array
    {
        if (substr_count($token, static::SEPARATOR) !== 1) {
            return null;
        }

        [$payload, $signature] = explode(static::SEPARATOR, $token);

        if ($this->sign($payload) !== $signature) {
            return null;
        }

        return $this->unserialize($this->decode($payload));
    }

    private function serialize(array $data): string
    {
        return substr(json_encode($data, JSON_UNESCAPED_SLASHES), 1, -1);
    }

    private function unserialize(string $encoded): array
    {
        return json_decode("[{$encoded}]", true);
    }

    private function encode(string $data): string
    {
        $data = array_map(fn ($char) => ord($char), str_split($data));

        $data = $this->convert($data, 256, static::TO_BASE);

        return implode('', array_map(fn ($index) => static::ALPHABET[$index], $data));
    }

    private function decode(string $data): string
    {
        $data = array_map(fn ($char) => strpos(static::ALPHABET, $char), str_split($data));

        $data = $this->convert($data, static::TO_BASE, 256);

        return implode('', array_map(fn ($char) => chr($char), $data));
    }

    private function convert(array $data, int $from, int $to): array
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
        return time();
    }
}
