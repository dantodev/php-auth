<?php namespace Dtkahl\Auth\Driver;

use Dtkahl\Auth\AbstractAuthDriver;
use Dtkahl\Auth\Auth;

class CustomAuthDriver extends AbstractAuthDriver
{

  public function __construct(Auth $auth, array $config)
  {
    if (array_diff_key(
        array_flip(["handleLogin", "storeSession", "retrieveSessionToken", "retrieveUser", "destroySession"]),
        $config
    )) {
      throw new \InvalidArgumentException("CustomAuthDriver config must contain the following keys: \"handleLogin\", \"storeSession\", \"retrieveSessionToken\", \"retrieveUser\", \"destroySession\"");
    }
    parent::__construct($auth, $config);
  }

  public function handleLogin($email, $hash)
  {
    return $this->_config["handleLogin"]($this->_auth, $email, $hash);
  }

  public function storeSession($session_token, $remember_token, $remember)
  {
    return $this->_config["storeSession"]($this->_auth, $session_token, $remember_token, $remember);
  }

  public function retrieveSessionToken()
  {
    return $this->_config["retrieveSessionToken"]($this->_auth);
  }

  public function retrieveUser($remember_token)
  {
    return $this->_config["retrieveUser"]($this->_auth, $remember_token);
  }

  public function validateSession()
  {
    return $this->_config["validateSession"]($this->_auth);
  }

  public function destroySession()
  {
    return $this->_config["destroySession"]($this->_auth);
  }

}