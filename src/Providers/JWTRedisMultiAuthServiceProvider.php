<?php

namespace SuStartX\JWTRedisMultiAuth\Providers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use SuStartX\JWTRedisMultiAuth\Cache\RedisCache;
use SuStartX\JWTRedisMultiAuth\Contracts\DataFactoryContract;
use SuStartX\JWTRedisMultiAuth\Contracts\RedisCacheContract;
use SuStartX\JWTRedisMultiAuth\Factories\BaseUserDataFactory;
use SuStartX\JWTRedisMultiAuth\Guards\JWTRedisMultiAuthGuard;
use SuStartX\JWTRedisMultiAuth\Hashers\JWTRedisMultiAuthHasher;
use SuStartX\JWTRedisMultiAuth\Helpers\GuardHelper;

class JWTRedisMultiAuthServiceProvider extends ServiceProvider
{
    public function register()
    {
        foreach (glob('../Helpers/*.php') as $file) {
            require_once $file;
        }

        $this->app->bind(DataFactoryContract::class, function ($app) {
            return new BaseUserDataFactory();
        });

        $this->app->bind(RedisCacheContract::class, function ($app) {
            return new RedisCache();
        });

    }

    public function boot()
    {
        // Provider
        Auth::provider('JWTRedisMultiAuthProvider', function ($app, array $config) {
            // TODO : Otomatik tespit etme tamamlanabilir..
            $cng = $config;
            $guard_name = GuardHelper::autoDetectGuard();
           // $guard_name = config('auth.defaults.guard');
            $guard = config('auth.guards.' . $guard_name);

            $config = config('auth.providers.' . $guard['provider']);

            $module_config = config('jwt_redis_multi_auth');

            // Önce $config ile gelen verileri kontrol et..
            if (array_key_exists('hasher', $config)) {
                // doğrudan geldi, önce değerlendir
                if ($config['hasher'] === 'default' || $config['hasher'] === 'bcrypt') {
                    $hasher = $app['hash'];
                } elseif ($config['hasher'] === 'jwt_redis_multi_auth') {
                    $hasher = new JWTRedisMultiAuthHasher();
                } else {
                    $hasher = new $config['hasher'];
                }
            } else {
                // $config ile hash bilgisi gelmediyse varsayılan modül ayarlarına bak..
                if ($module_config['hasher'] === 'default' || $module_config['hasher'] === 'bcrypt') {
                    $hasher = $app['hash'];
                } elseif ($module_config['hasher'] === 'jwt_redis_multi_auth') {
                    $hasher = new JWTRedisMultiAuthHasher();
                } else {
                    $hasher = new $module_config['hasher'];
                }
            }

            // Data factory hazırlanıyor
            if (array_key_exists('data_factory', $config)) {
                $data_factory = app($config['data_factory']);
            } else {
                $data_factory = new BaseUserDataFactory();
            }

            return new JWTRedisMultiAuthUserProvider(
                $hasher,
                $config['model'],
                $data_factory
            );
        });

        // Guard
        Auth::extend('JWTRedisMultiAuthGuard', function ($app, $name, array $config) {
            // TODO : Otomatik tespit etme tamamlanabilir..
            $guard_name = GuardHelper::autoDetectGuard();
            //$guard_name = config('auth.defaults.guard');
            $config = config('auth.guards.' . $guard_name);

            $jwt = $app['tymon.jwt'];

            $provider = Auth::createUserProvider($guard_name);

            $request = $app['request'];
            $event_dispatcher = $app['events'];

            return new JWTRedisMultiAuthGuard(
                $jwt,
                $provider,
                $request,
                $event_dispatcher,
                $config
            );
        });

        // Hasher
        $this->app->bind('JWTRedisMultiAuthHasher', function () {
            $config = config('hashing.bcrypt');
            return new JWTRedisMultiAuthHasher($config);
        });

        // Config
        $this->mergeConfigFrom(__DIR__ . '/../../config/config.php', 'jwt_redis_multi_auth');
        $this->publishes([
            __DIR__ . '/../../config/config.php' => config_path('jwt_redis_multi_auth.php')
        ], 'config');

        // Model Observer
        $providers = config('auth.providers');
        $prefix = config('jwt_redis_multi_auth.guard_prefix');
        foreach ($providers as $provider => $config) {
            if (str_starts_with($provider, $prefix)) {
                $model = $config['model'];
                if (class_exists($model)) {
                    $model::observe(config('jwt_redis_multi_auth.observer'));
                }
            }
        }
    }
}
