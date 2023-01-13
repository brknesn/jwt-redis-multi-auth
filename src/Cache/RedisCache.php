<?php

namespace SuStartX\JWTRedisMultiAuth\Cache;

use Illuminate\Support\Facades\Redis;
use SuStartX\JWTRedisMultiAuth\Contracts\RedisCacheContract;

class RedisCache implements RedisCacheContract
{
    protected $data;
    private $time;
    protected $key;

    public function key(string $key): RedisCacheContract
    {
        $this->key = $key;

        return $this;
    }

    public function data($data): RedisCacheContract
    {
        $this->data = $data;

        return $this;
    }

    public function getCache()
    {
        $data = Redis::connection('cache')->get($this->key);
        if (!is_null($data)) {
            return $this->unserialize($data);
        }

        return $data;
    }

    public function removeCache()
    {
        return Redis::connection('cache')->del($this->key);
    }

    public function refreshCache()
    {
        if (!$this->getCache()) {
            return false;
        }

        $this->key($this->key)->removeCache();

        return $this->key($this->key)->data($this->data)->cache();
    }

    public function cache()
    {
        $this->setTime();

        Redis::connection('cache')->setex($this->key, $this->time, $this->serialize($this->data));
        return $this->data;
    }

    private function setTime(): RedisCacheContract
    {
        $this->time = (config('jwt_redis_multi_auth.redis_ttl_jwt') ? config('jwt.ttl') : config('jwt_redis_multi_auth.redis_ttl')) * 60;

        return $this;
    }

    protected function serialize($value)
    {
        if (config('jwt_redis_multi_auth.igbinary_serialization')) {
            return igbinary_serialize($value);
        }

        return serialize($value);
    }

    protected function unserialize($value)
    {
        if (config('jwt_redis_multi_auth.igbinary_serialization')) {
            return igbinary_unserialize($value);
        }

        return unserialize($value);
    }
}
