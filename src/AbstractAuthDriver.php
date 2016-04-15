<?php namespace Dtkahl\Auth;

abstract class AbstractAuthDriver
{

  protected $_auth;
  protected $_config;

  public function __construct(Auth $auth, array $config = [])
  {
    $this->_auth = $auth;
    $this->_config = $config;
  }

  /**
   * Handle email/hash, return user implementing Dtkahl/Auth/AuthUserInterface
   *
   * @param string $email
   * @param string $hash
   * @return AuthUserInterface
   */
  abstract public function handleLogin($email, $hash);

  /**
   * store session token for validation in later requests, return value will be returned by Auth::login()
   *
   * @param string $session_token
   * @param string $remember_token
   * @param bool $remember
   * @return bool
   */
  abstract public function storeSession($session_token, $remember_token, $remember);

  /**
   * retrieve and return session_token from request
   *
   * @return string|null
   */
  abstract public function retrieveSessionToken();

  /**
   * retrieve and return user implementing Dtkahl/Auth/AuthUserInterface by remember_token
   *
   * @param string $remember_token
   * @return AuthUserInterface
   */
  abstract public function retrieveUser($remember_token);

  /**
   * delete remember_token from user, unset session_token
   *
   * @return bool
   */
  abstract public function destroySession();

}