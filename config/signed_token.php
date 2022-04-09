<?php

declare(strict_types=1);

return [
    'key'    => env('TOKEN_KEY', ENV('APP_KEY')),
    'algo'   => 'sha256',
    'length' => 16,
];
