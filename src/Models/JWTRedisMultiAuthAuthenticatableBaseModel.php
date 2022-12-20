<?php

namespace SuStartX\JWTRedisMultiAuth\Models;

use SuStartX\JWTRedisMultiAuth\Traits\JWTRedisHasRoles;

class JWTRedisMultiAuthAuthenticatableBaseModel extends BaseModel
{
    use JWTRedisHasRoles;

    public $customClaims = [
        'stripe_id' => 'string',
    ];

    public function addCustomClaims(array $claims){
        $this->customClaims = array_merge($this->customClaims, $claims);
    }
    public function deleteCustomClaims(array $claims){
        foreach ($claims as $claim) {
            unset($this->customClaims[$claim]);
        }
    }

    public function getModelClassName(){
        return (new \ReflectionClass($this))->getShortName();
    }

    public function getRedisKey()
    {
        return strtolower($this->getModelClassName()) . '_' . $this->getKey();
    }
}
