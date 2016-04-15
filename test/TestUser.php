<?php namespace Dtkahl\AuthTest;

use Dtkahl\Auth\AuthUserInterface;

class TestUser implements AuthUserInterface
{

  private $remember_token;

  public function getIdUser()
  {
    return 1;
  }

  public function setRememberToken($remember_token)
  {
    $this->remember_token = $remember_token;
  }

  public function getRememberToken()
  {
    return $this->remember_token;
  }

}