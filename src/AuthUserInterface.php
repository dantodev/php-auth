<?php namespace Dtkahl\Auth;

interface AuthUserInterface
{

    /**
     * @return mixed
     */
    public function getIdUser();

    /**
     * @return string
     */
    public function retrieveRememberToken();

    /**
     * @param $remember_token
     */
    public function storeRememberToken($remember_token);

    // TODO add handleLogin etc

}