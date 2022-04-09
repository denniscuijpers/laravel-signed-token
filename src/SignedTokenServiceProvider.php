<?php

declare(strict_types=1);

namespace DennisCuijpers\SignedToken;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\ServiceProvider;

class SignedTokenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom($this->configPath(), 'signed_token');

        $this->app->singleton('signed_token', function (Container $app) {
            return new SignedToken($app['config']['signed_token']);
        });

        $this->app->alias('signed_token', SignedToken::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([$this->configPath() => config_path('signed_token.php')], 'signed_token');
        }
    }

    public function provides()
    {
        return [
            'signed_token',
        ];
    }

    private function configPath(): string
    {
        return __DIR__ . '/../config/signed_token.php';
    }
}
