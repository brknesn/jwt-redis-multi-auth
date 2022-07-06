<?php

namespace SuStartX\JWTRedisMultiAuth\Guards;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\JWT;
use PHPOpenSourceSaver\JWTAuth\JWTGuard;
use SuStartX\JWTRedisMultiAuth\Facades\RedisCache;

class JWTRedisMultiAuthGuard extends JWTGuard
{
    private $config = [];

    protected $lastAttempted = null;

    public function __construct(JWT $jwt, UserProvider $provider, Request $request, Dispatcher $eventDispatcher, $config)
    {
        parent::__construct($jwt, $provider, $request, $eventDispatcher);

        $this->config = $config;
    }

    public function getConfig($key = null){
        if(is_null($key)){
            return $this->config;
        }
        return array_key_exists($key, $this->config) ? $this->config[$key] : null;
    }

    // ----------------------------------------------------------------------------------------------------
    // Login methods
    // ----------------------------------------------------------------------------------------------------
    public function attempt(array $credentials = [], $login = true, $data_factory = null)
    {
        $this->lastAttempted = $this->provider->retrieveByCredentials($credentials);

        $this->fireAttemptEvent($credentials);

        $result_type = 'SUCCESS';
        $status = false;
        $token = null;

        if ($this->lastAttempted){
            $this->lastAttempted = $this->prepareLastAttempedData($this->lastAttempted, $data_factory);
            $result_type = $this->checkLastAttemptedLoginStatus();

            if ($this->hasValidCredentials($this->lastAttempted, $credentials)) {
                $this->refreshAuthFromRedis($this->lastAttempted);

                if ($login){
                    $token = $this->login($this->lastAttempted);
                    $this->setUser($this->lastAttempted);
                    $this->storeRedis(true);
                }else{
                    $token = true;
                }

                $status = true;
            }else{
                $this->fireFailedEvent($this->lastAttempted, $credentials);
            }
        }else{
            $this->fireFailedEvent($this->lastAttempted, $credentials);
        }

        return [
            'status' => $status,
            'type' => $result_type,
            'token' => $token,
        ];
    }

    public function attempt_2fa_step_1(array $credentials = [])
    {
        $this->lastAttempted = $this->provider->retrieveByCredentials($credentials);

        $this->fireAttemptEvent($credentials);

        $result_type = 'SUCCESS';
        $status = false;

        if($this->lastAttempted){
            $result_type = $this->checkLastAttemptedLoginStatus();

            if ($this->hasValidCredentials($this->lastAttempted, $credentials)) {
                $status = true;
            }else{
                $this->fireFailedEvent($this->lastAttempted, $credentials);
            }
        }else{
            $this->fireFailedEvent($this->lastAttempted, $credentials);
        }

        return [
            'status' => $status,
            'type' => $result_type,
            'authenticable' => $this->lastAttempted
        ];
    }

    public function attempt_2fa_step_2($code, $login = true, $data_factory = null)
    {
        $credentials = [
            'code' => $code,
        ];

        $this->lastAttempted = $this->provider->retrieveBy2FACode($code);

        $this->fireAttemptEvent($credentials);

        $result_type = 'SUCCESS';
        $status = false;
        $token = null;

        if ($this->lastAttempted){
            $this->lastAttempted = $this->prepareLastAttempedData($this->lastAttempted, $data_factory);
            $result_type = $this->checkLastAttemptedLoginStatus();
            $this->refreshAuthFromRedis($this->lastAttempted);
            $token = $this->login($this->lastAttempted);
            $this->setUser($this->lastAttempted);
            $this->storeRedis(true);
            $status = true;
        }else{
            $this->fireFailedEvent($this->lastAttempted, $credentials);
        }

        return [
            'status' => $status,
            'type' => $result_type,
            'authenticable' => $this->lastAttempted,
            'token' => $token,
        ];
    }
    // ----------------------------------------------------------------------------------------------------

    // ----------------------------------------------------------------------------------------------------
    // Provider methods
    // ----------------------------------------------------------------------------------------------------
    public function user()
    {
        return $this->user ?? $this->retreiveByRedis();
    }

    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            $this->storeRedis(true);

            return true;
        }

        return false;
    }
    // ----------------------------------------------------------------------------------------------------

    // ----------------------------------------------------------------------------------------------------
    // Redis methods
    // ----------------------------------------------------------------------------------------------------
    public function retreiveByRedis()
    {
        return $this->request->authedUser ?? $this->getOrSetToRedis();
    }

    public function getOrSetToRedis()
    {
        return $this->getAuthFromRedis() ?? $this->setAuthToRedis();
    }

    public function getAuthFromRedis()
    {
        return RedisCache::key($this->getRedisKeyFromClaim())->getCache();
    }

    public function setAuthToRedis()
    {
        if ($this->request->bearerToken()) {
            // TODO : Veritabanından kontrol edilmeli, girişine engel herhangi bir durum yoksa yeni veriler alınarak redis güncellenmeli
            return $this->storeRedis();
        }

        // If token not found, we need to return null.
        // Because Laravel's need this user object even if empty.
        return null;
    }

    public function removeAuthFromRedis()
    {
        return RedisCache::key($this->getRedisKeyFromClaim())->removeCache();
    }

    public function getRedisKeyFromClaim()
    {
        return $this->request->jwt_guard_key . '_' . $this->request->claim;
    }

    public function storeRedis($login = false)
    {
        // Giriş yapmaya çalışıyorsa $this->lastAttempt içindeki key değeri alınıyor.
        if($login)
        {
            return RedisCache::key($this->lastAttempted->getRedisKey())->data($this->lastAttempted)->cache();
        }
        else
            // Giriş dışında kayıt gerekiyorsa JWT içindeki key değeri alınıyor.
        {
            return RedisCache::key($this->getRedisKeyFromClaim())->data(JWTAuth::parseToken()->authenticate()->load(config('jwt_redis_multi_auth.cache_relations')))->cache();
        }
    }

    public function refreshAuthFromRedis($user)
    {
        return RedisCache::key($user->getRedisKey())->data($user)->refreshCache();
    }
    // ----------------------------------------------------------------------------------------------------

    // ----------------------------------------------------------------------------------------------------
    // Helper methods
    // ----------------------------------------------------------------------------------------------------
    /**
     * Verilen kullanıcı bilgisini token oluşturabilecek şekilde hazırlıyor.
     *
     * @param $authenticable
     * @param $data_factory
     * @return mixed
     */
    public function prepareLastAttempedData($authenticable, $data_factory = null){
        $prefix = config('jwt_redis_multi_auth.guard_prefix');

        $authenticable->addCustomClaims([
            config('jwt_redis_multi_auth.jwt_guard_key') => str_replace($prefix, '', $this->getConfig('provider')),
        ]);

        if ($data_factory === null && config('jwt_redis_multi_auth.disable_default_user_data_factory') === false){
            $data_factory = auth()->guard()->getProvider()->getDataFactory();
        }

        if($data_factory){
            $authenticable->addCustomClaims([
                'user' => $data_factory->data($authenticable)
            ]);
        }

        return $authenticable;
    }

    private function checkLastAttemptedLoginStatus(){
        $result_type = 'SUCCESS';

        // E-posta adresini doğrulamış mı?
        if(!$this->lastAttempted->hasVerifiedEmail()){
            $result_type = 'EMAIL_NOT_VERIFIED';
        }

        // Yasaklanmış mı?
        if ($this->lastAttempted->is_banned){
            $result_type = 'BANNED';
        }

//        if (config('jwt_redis_multi_auth.check_banned_user')) {
//            if (!$user->checkUserStatus()) {
//                throw new AuthorizationException('Your account has been blocked by the administrator.');
//            }
//        }

        return $result_type;
    }

    public function setLastAttempted(Authenticatable $authenticatable)
    {
        $this->lastAttempted = $authenticatable;
    }
    // ----------------------------------------------------------------------------------------------------

    public function check(){
        return (bool)$this->getAuthFromRedis();
    }
}
