<?php namespace Dtkahl\Auth;

class Auth
{

  private $_driver;
  private $_app_salt;

  private $_user = null;
  private $_authenticated = false;
  private $_last_session_token = null;

  /**
   * Auth constructor.
   * @param $driver_class
   * @param array $config
   * @param string $app_salt
   */
  public function __construct($driver_class, array $config = [], $app_salt = "")
  {
    $driver = new $driver_class($this, $config);

    if (!is_subclass_of($driver_class, AbstractAuthDriver::class)) {
      throw new \RuntimeException("\$class [$driver_class] must extend AbstractAuthDriver.");
    }

    $this->_driver = $driver;
    $this->_app_salt = $app_salt;
  }

  /**
   * @return AbstractAuthDriver
   */
  public function getDriver()
  {
    return $this->_driver;
  }

  /**
   * @param string $email
   * @param string $password
   * @param bool $remember
   * @return bool
   */
  public function login($email, $password, $remember = false)
  {
    $hash = self::hash($password, $this->_app_salt );
    $user = $this->getDriver()->handleLogin($email, $hash);

    if ($user instanceof AuthUserInterface) {
      $this->_user = $user;
      $this->_authenticated = true;

      $session_token = $this->generateSessionToken($user->getIdUser());
      $remember_token = $this->generateRememberToken($session_token);

      return $this->getDriver()->storeSession($session_token, $remember_token, $remember);
    }

    return false;
  }

  /**
   * @return bool
   */
  public function logout()
  {
    if ($this->isAuthenticated()) {
      if ($this->getDriver()->destroySession()) {
        $this->_user = null;
        $this->_authenticated = false;
        return true;
      }
    }
    return false;
  }

  /**
   * @return bool
   */
  public function validateSession()
  {
    $session_token = $this->getDriver()->retrieveSessionToken();

    if ($session_token !== null) {

      $remember_token = $this->generateRememberToken($session_token);
      $user = $this->getDriver()->retrieveUser($remember_token);

      if ($user instanceof AuthUserInterface) {
        $this->_user = $user;
        $this->_authenticated = true;
        return true;
      }
    }

    return false;
  }

  /**
   * @return string|null
   */
  public function getLastSessionToken()
  {
    return $this->_last_session_token;
  }

  /**
   * @return bool
   */
  public function isAuthenticated()
  {
    return $this->_authenticated;
  }

  /**
   * @return AuthUserInterface|null
   */
  public function getUser()
  {
    return $this->_user;
  }

  /**
   * @return string
   */
  public function getAppSalt()
  {
    return $this->_app_salt;
  }

  /**
   * @param $user_id
   * @return string
   */
  private function generateSessionToken($user_id)
  {
    return self::hash($user_id . time(), $this->getAppSalt());
  }

  /**
   * @param $session_token
   * @return string
   */
  private function generateRememberToken($session_token)
  {
    return self::hash(self::getIp() . $session_token, $this->getAppSalt());
  }

  /**
   * @param string $string
   * @param string|null $salt
   * @return mixed
   */
  public static function hash($string, $salt = null)
  {
    $salt = $salt ?: self::random_salt();
    if (!preg_match("/^[a-zA-Z0-9.\\/]{22,}$/", $salt)) {
      throw new \RuntimeException("salt must follow the following condition ^[a-zA-Z0-9.\\/]{22,}$");
    }
    return crypt ( $string, "\$2a\$08\$$salt" );
  }

  /**
   * @param int $length
   * @return string
   */
  public static function random_salt($length = 22)
  {
    return substr(str_shuffle('./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') , 0, $length);
  }

  private static function getIp()
  {
    $headers = function_exists('apache_request_headers') ? apache_request_headers() : $_SERVER;

    if (
        array_key_exists('X-Forwarded-For', $headers) &&
        filter_var($headers['X-Forwarded-For'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
    ) {
      return $headers['X-Forwarded-For'];
    } elseif (
        array_key_exists( 'HTTP_X_FORWARDED_FOR', $headers) &&
        filter_var($headers['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
    ) {
      return $headers['HTTP_X_FORWARDED_FOR'];
    } else if (
        array_key_exists( 'REMOTE_ADDR', $headers) &&
        filter_var($headers['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
    ) {
      return $_SERVER['REMOTE_ADDR'];
    } else {
      return null;
    }
  }

}