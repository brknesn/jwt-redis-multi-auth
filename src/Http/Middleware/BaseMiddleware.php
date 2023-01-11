<?php

namespace SuStartX\JWTRedisMultiAuth\Http\Middleware;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use SuStartX\JWTRedisMultiAuth\Response\JWTRedisMultiAuthErrorResponse;
use Symfony\Component\HttpFoundation\Response;

class BaseMiddleware
{
    /**
     *  If you don't use Authentication Middleware before that Middleware,
     *  application need to set a Claim (by Token) in Request object for
     *  using Laravel's Auth facade.
     *
     * @param $request
     *
     * @return mixed
     */
    public function setIfClaimIsNotExist(Request $request){
        if ($request->claim === null) {
            $default_guard_name = config('auth.defaults.guard');
            $token_cookie = \Cookie::get($default_guard_name.'_'.env('COOKIE_NAME'));
            $token_bearer = request()->bearerToken();
            $token = $token_cookie ?: $token_bearer ?: null;
            $payload = JWTAuth::setToken($token)->getPayload();
            $request->claim = $payload->get('sub');
            $request->jwt_guard_key = $payload->get(config('jwt_redis_multi_auth.jwt_guard_key'));
        }
        return $request;
    }

    /**
     * This first request always comes from Redis,
     * then will always be stored in this Request object.
     *
     * @param $request
     */
    protected function setAuthedUser($request)
    {
        $request->authedUser = Auth::user();
    }

    /**
     * @param $exception
     *
     * @return JsonResponse
     */
    protected function getErrorResponse($exception, $http_code)
    {
        $exception = is_string($exception) ?? class_basename($exception);
        $error = config('jwt_redis_multi_auth.errors.'. $exception) ?? config('jwt_redis_multi_auth.errors.default');

        return response()->json(new JWTRedisMultiAuthErrorResponse(
            $http_code,
            $error['title'],
            $error['message'],
            $error['code'],
        ), $http_code);
    }
}
