<?php

namespace SuStartX\JWTRedisMultiAuth\Providers;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\UserProvider as UserProviderContract;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Support\Arrayable;
use SuStartX\JWTRedisMultiAuth\Contracts\DataFactoryContract;
use Closure;

class JWTRedisMultiAuthUserProvider extends EloquentUserProvider implements UserProviderContract
{
    protected DataFactoryContract $data_factory;

    public function __construct(HasherContract $hasher, $model, DataFactoryContract $data_factory)
    {
        parent::__construct($hasher, $model);
        $this->data_factory = $data_factory;
    }

    /**
     * Verilen şartlara göre veritabanında sorgulama yapar.
     *
     * @param array $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Builder|\Illuminate\Database\Eloquent\Model|object|void|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        $credentials = array_filter(
            $credentials,
            fn ($key) => ! str_contains($key, 'password'),
            ARRAY_FILTER_USE_KEY
        );

        if (empty($credentials)) {
            return;
        }

        return $this->getUserFromDb($credentials);
    }

    /**
     * 2FA kodu ile veritabanında sorgulama yapar.
     *
     * @param $code
     * @return \Illuminate\Database\Eloquent\Builder|\Illuminate\Database\Eloquent\Model|object|null
     */
    public function retrieveBy2FACode($code)
    {
        $credentials = [
            'two_fa_code' => $code,
            'two_fa_expiration' => function($q){
                $q->where('two_fa_expiration', '>=', now());
            }
        ];

        return $this->getUserFromDb($credentials);
    }

    /**
     * Şartlara uygun sorgu yaparak bulduğu kaydı döndürür.
     *
     * @param $credentials
     * @return \Illuminate\Database\Eloquent\Builder|\Illuminate\Database\Eloquent\Model|object|null
     */
    private function getUserFromDb($credentials){
        $query = $this->newModelQuery()
            ->with(config('jwt_redis_multi_auth.cache_relations'))
        ;

        foreach ($credentials as $key => $value) {
            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } elseif ($value instanceof Closure) {
                $value($query);
            } else {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }

    /**
     * @return DataFactoryContract
     */
    public function getDataFactory(){
        return $this->data_factory;
    }
}
