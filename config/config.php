<?php

return [
    // default (= 'bcrypt'), 'jwt_redis_multi_auth', 'new hasher class path'
    'hasher' => 'default',

    // Kullanıcı giriş yaptığında bu bilgileri de 'with' ile veritabanından alır.
    /*
    |--------------------------------------------------------------------------
    | Cache This Relations When User Has Authenticated
    |--------------------------------------------------------------------------
    |
    | You can add this array to your own relations, anything you want to store
    | in Redis. We recommend caching only roles and permissions here as much as
    | possible.
    |
    */
    'cache_relations' => [
        'roles.permissions',
        'permissions',
    ],

    // Bu değer autoDetectGuard() içinde otomatik guard tespiti için kullanılıyor.
    'guard_prefix' => 'jwt_',

    // Farklı guard ile giriş yapmak istiyorsa gelebilecek input key ne olabilir?
    'login_type_guard_input_names' => [
        'login_type',
        'guard',
        'type',
    ],

    // Giriş işleminde önceden token varsa geçici olarak iptal etmek için login url bilinmeli.
    'login_route_name' => 'auth.login',
    'login_2fa_code_route_name' => 'auth.2fa_code',

    // JWT içinde guard bilgisinin hangi key ile saklanacağını belirler.
    'jwt_guard_key' => 'type',

    // Modelden gelen verinin biçimlendirmesinin iptal edilip edilmeme durumu
    'disable_default_user_data_factory' => true,

    /*
    |--------------------------------------------------------------------------
    | JWTRedisMultiAuth User Model Observer
    |--------------------------------------------------------------------------
    |
    | This observer class, listening all events on your user model. Is triggered
    | when you assign roles & permissions to user, or update and delete to
    | your user model.
    |
    */
    'observer' => \SuStartX\JWTRedisMultiAuth\Observers\AuthAuthenticatableModelRedisObserver::class,

    /*
    |--------------------------------------------------------------------------
    | Store on Redis up to jwt_ttl value.
    |--------------------------------------------------------------------------
    |
    | If it's option is true, user stored in Redis up to jwt_ttl value time.
    |
    */
    'redis_ttl_jwt' => true,

    /*
    |--------------------------------------------------------------------------
    | Store on Redis up to specific time
    |--------------------------------------------------------------------------
    |
    |  User stored in Redis redis_ttl value time.
    |
    */
    'redis_ttl' => env('JWT_REDIS_MULTI_AUTH_REDIS_TTL', 60),


    'jwt_ttl' => env('JWT_REDIS_MULTI_AUTH_JWT_TTL', 60),
    /*
    |--------------------------------------------------------------------------
    | Igbinary Serialization
    |--------------------------------------------------------------------------
    |
    | Igbinary Serialization provides a better performance and lower memory
    | usage than PHP Serialization.
    |
    | * ~ Don't forget to enable igbinary extension if this option is true. ~ *
    |
    */
    'igbinary_serialization' => env('JWT_REDIS_MULTI_AUTH_IGBINARY_SERIALIZATION', false),

    /*
    |--------------------------------------------------------------------------
    | Status Column For Banned User Checking
    |--------------------------------------------------------------------------
    |
    | You can set your specific column name of your user model.
    |
    */
    'status_column_title' => 'status',

    /*
    |--------------------------------------------------------------------------
    | Banned User Checking
    |--------------------------------------------------------------------------
    |
    | If the check_banned_user option is true, that users cannot access
    | the your application.
    |
    */
    'check_banned_user' => env('JWT_REDIS_MULTI_AUTH_CHECK_BANNED_USER', false),

    /*
    |--------------------------------------------------------------------------
    | Restricted statuses For Banned User Checking
    |--------------------------------------------------------------------------
    |
    | If the user has one of these statuses and trying to reach your application,
    | JWTRedisMultiAuth throws AccountBlockedException.
    | You can set the message (check it errors array) that will return in this
    | exception.
    |
    */
    'banned_statuses' => [
        'banned',
        'deactivate',
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Prefix
    |--------------------------------------------------------------------------
    |
    | If it's user id is 1, this user stored in Redis as auth_1.
    |
    */
    'jwt_redis_multi_auth_prefix' => env('JWT_REDIS_MULTI_AUTH_PREFIX', 'auth_'),

    /*
    |--------------------------------------------------------------------------
    | Observer Events Are Queued
    |--------------------------------------------------------------------------
    |
    | If this option is true, model's events are processed as a job on queue.
    | The job will be executed after the database transactions are commit.
    |
    | * ~ Don't forget to run Queue Worker if this option is true. ~ *
    |
    */
    'observer_events_queue' => env('JWT_REDIS_MULTI_AUTH_OBSERVER_EVENTS_QUEUE', false),

    /*
    |--------------------------------------------------------------------------
    | Customize All Exception Messages and Codes
    |--------------------------------------------------------------------------
    |
    | You can customize error code,message,title for your application.
    |
    */
    'errors' => [

        'default' => [
            'title'   => 'Operation Failed',
            'message' => 'An error occurred.',
            'code'    => 0,
        ],

        'AccountBlockedException' => [
            'title'   => 'Operation Failed',
            'message' => 'Your account has been blocked by the administrator.',
            'code'    => 1,
        ],

        'TokenNotProvidedException' => [
            'title'   => 'Operation Failed',
            'message' => 'Token not provided.',
            'code'    => 2,
        ],

        'JWTException' => [
            'title'   => 'Operation Failed',
            'message' => 'A token is required',
            'code'    => 3,
        ],

        'TokenBlacklistedException' => [
            'title'   => 'Operation Failed',
            'message' => 'The token has been blacklisted.',
            'code'    => 4,
        ],

        'TokenExpiredException' => [
            'title'   => 'Operation Failed',
            'message' => 'Token has expired.',
            'code'    => 5,
        ],

        'TokenInvalidException' => [
            'title'   => 'Operation Failed',
            'message' => 'Could not decode or verify token.',
            'code'    => 6,
        ],

        'PermissionException' => [
            'title'   => 'Operation Failed',
            'message' => 'User does not have the right permissions.',
            'code'    => 7,
        ],

        'RoleException' => [
            'title'   => 'Operation Failed',
            'message' => 'User does not have the right roles.',
            'code'    => 8,
        ],

        'RoleOrPermissionException' => [
            'title'   => 'Operation Failed',
            'message' => 'User does not have the right roles or permissions.',
            'code'    => 9,
        ],
    ],

    'exception_groups' => [
        'JWTAuth' => [
            \PHPOpenSourceSaver\JWTAuth\Exceptions\InvalidClaimException::class => [
                'title' => 'InvalidClaimException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
            \PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException::class => [
                'title' => 'JWTException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
            \PHPOpenSourceSaver\JWTAuth\Exceptions\PayloadException::class => [
                'title' => 'PayloadException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
            \PHPOpenSourceSaver\JWTAuth\Exceptions\SecretMissingException::class => [
                'title' => 'SecretMissingException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
            \PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException::class => [
                'title' => 'TokenBlacklistedException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
            \PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException::class => [
                'title' => 'TokenExpiredException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
            \PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException::class => [
                'title' => 'TokenInvalidException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
            \PHPOpenSourceSaver\JWTAuth\Exceptions\UserNotDefinedException::class => [
                'title' => 'UserNotDefinedException',
                'message' => '',
                'status' => false,
                'http_code' => 401,
            ],
        ]
    ]
];
