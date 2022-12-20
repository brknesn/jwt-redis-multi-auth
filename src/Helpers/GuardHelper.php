<?php

namespace SuStartX\JWTRedisMultiAuth\Helpers;

use Cookie;
use Exception;
use PHPOpenSourceSaver\JWTAuth\Token;

class GuardHelper
{
    public static function autoDetectGuard()
    {
        $request = request();
        $prefix = config('jwt_redis_multi_auth.guard_prefix');
        $default_guard_name = config('auth.defaults.guard');

        // ----------------------------------------------------------------------------------------------------
        // Guard ismi request içinden tespit edilmeye çalışılıyor..
        // ----------------------------------------------------------------------------------------------------
        // Request içinde izin verilen key değerlerinden birisi varsa guard değeri request içinden tespit edilir
        $login_type_guard_input_names = config('jwt_redis_multi_auth.login_type_guard_input_names');
        $request_guard_name = null;
        foreach ($login_type_guard_input_names as $login_type_guard_input_name) {
            if ($request->has($login_type_guard_input_name) && $request->get($login_type_guard_input_name) != '') {
                $request_guard_name = $prefix . $request->get($login_type_guard_input_name);
                break;
            }
        }
        // ----------------------------------------------------------------------------------------------------

        // Giriş yapmak istiyorsa..
        if (
            $request->route() &&
            (
                config('jwt_redis_multi_auth.login_route_name') === $request->route()->getName() ||
                config('jwt_redis_multi_auth.login_2fa_code_route_name') === $request->route()->getName()
            )
        ) {
            if (!is_null($request_guard_name)) {
                $guard_name = $request_guard_name;
            } else {
                $guard_name = $default_guard_name;
            }
        } else {
            $token_cookie = Cookie::get(env('COOKIE_NAME'));
            $token_bearer = request()->bearerToken();
            $token = $token_cookie ?: $token_bearer ?: null;

            if ($token) {
                try {
                    $decoded_token = app()->get('tymon.jwt.manager')->decode(new Token($token));
                    $guard = $decoded_token->get(config('jwt_redis_multi_auth.jwt_guard_key'));
                    // Oturum varsa oturumdan hangi guard ile çalıştığı tespit edildi
                    $guard_name = $prefix . $guard;
                } catch (Exception $exception) {
                    $guard_name = $default_guard_name;
                }
            } else {
                if (!is_null($request_guard_name)) {
                    $guard_name = $request_guard_name;
                } else {
                    $guard_name = $default_guard_name;
                }
            }
        }

        // Olmayan guard ismiyle istekte bulunulduğunda hata vermemesi için varsayılan guard ile işlem yapılıyor.
        $all_guard = config('auth.guards');
        if (!array_key_exists($guard_name, $all_guard)) {
            $guard_name = $default_guard_name;
        }

        return $guard_name;
    }
}
