<?php namespace Dtkahl\Auth;

use Dtkahl\ArrayTools\Map;
use Interop\Container\ContainerInterface;
use Slim\Http\Response;

class Auth
{

  /** @var Map */
  private $_options;

  /** @var ContainerInterface */
  private $_container;

  /** @var \Slim\Http\Cookies $cookies */
  private $_cookies;

  /** @var AuthUserInterface */
  private $_user = null;

  private $_authenticated = false;

  /**
   * @param Map $options
   * @param ContainerInterface $container
   */
  public function configure(Map $options, ContainerInterface $container)
  {
    $require = ["salt", "handleLogin", "retrieveUser"];
    if (!$options->hasKeys($require)) {
      throw new \RuntimeException(sprintf("Auth Middleware require '%s' options.", implode("', '", $require)));
    }

    $this->_options   = $options;
    $this->_container = $container;
    $this->_cookies   = $container->get($options->get("cookies_container", "cookies"));
  }

  /**
   * @param Response $response
   * @param string $email
   * @param string $password
   * @param bool $remember
   * @return bool
   */
  public function login(Response $response, $email, $password, $remember = false)
  {
    $hash = self::hash($password, $this->_options->get("salt"));
    $handle_login = $this->_options->get("handleLogin");
    if (is_callable($handle_login)) {
      $user = $handle_login($email, $hash);
    } else {
      throw new \RuntimeException("The option 'handleLogin' must be callable.");
    }

    if ($user instanceof AuthUserInterface) {
      $this->_user = $user;
      $this->_authenticated = true;

      $session_token = md5($this->generateSessionToken($user->getIdUser()));
      $remember_token = $this->generateRememberToken($session_token);
      $this->getUser()->storeRememberToken($remember_token);

      $cookie = $this->_options->get("default_cookie", []);
      $lifetime = $remember ?
          $this->_options->get('lifetime_remember', 2592000) :
          $this->_options->get('lifetime', 21600);
      $cookie["expires"] = time() + $lifetime;
      $cookie["value"] = $session_token;

      $this->_cookies->set('session_token', $cookie);
      return $response->withHeader('Set-Cookie', $this->_cookies->toHeaders());
    }

    return $response;
  }

  /**
   * @param Response $response
   * @return Response
   */
  public function logout(Response $response)
  {
    if ($this->isAuthenticated()) {
      $this->_cookies->set("session_token", [
        "value" => "",
        "expires" => time()-3600
      ]);
      $this->getUser()->storeRememberToken(null);
      $this->_user = null;
      $this->_authenticated = false;
      return $response->withHeader('Set-Cookie', $this->_cookies->toHeaders());
    }
    return $response;
  }

  /**
   * @return bool
   */
  public function validateSession()
  {
    $session_token  = $this->_cookies->get("session_token");

    if (!is_null($session_token)) {
      $remember_token = $this->generateRememberToken($session_token);
      $retrieveUser = $this->_options->get("retrieveUser");

      if (is_callable($retrieveUser)) {
        $user = $retrieveUser($remember_token);
        if ($user instanceof AuthUserInterface) {
          $this->_user = $user;
          $this->_authenticated = true;
          return true;
        }
      } else {
        throw new \RuntimeException("The option 'retrieveUser' must be callable.");
      }
    }

    return false;
  }

  /**
   * @return bool
   */
  public function isAuthenticated()
  {
    return $this->_authenticated;
  }

  /**
   * @return AuthUserInterface
   */
  public function getUser()
  {
    return $this->_user;
  }

  /**
   * @param $user_id
   * @return string
   */
  private function generateSessionToken($user_id)
  {
    return self::hash($user_id . time(), $this->_options->get("salt"));
  }

  /**
   * @param $session_token
   * @return string
   */
  private function generateRememberToken($session_token)
  {
    if ($this->_options->get('use_ip', true)) {
      return self::hash(self::getIp() . $session_token, $this->_options->get("salt"));
    } else {
      return self::hash($session_token, $this->_options->get("salt"));
    }
  }

  /**
   * @param string $string
   * @param string|null $salt
   * @return mixed
   */
  public static function hash($string, $salt = null)
  {
    $salt = $salt ?: self::randomSalt();
    if (!preg_match("/^[a-zA-Z0-9.\\/]{22,}$/", $salt)) {
      throw new \RuntimeException("salt must follow the following condition ^[a-zA-Z0-9.\\/]{22,}$");
    }
    return crypt($string, '$2a$08$' . $salt);
  }

  /**
   * @param int $length
   * @return string
   */
  public static function randomSalt($length = 22)
  {
    return substr(str_shuffle('./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') , 0, $length);
  }

  private static function getIp()
  {
    $env = function_exists('apache_request_headers') ? apache_request_headers() : $_SERVER;
    $headers = ['X-Forwarded-For', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];

    foreach ($headers as $header) {
      if (validateIP($env, $header)) {
        return $env[$header];
      }
    }
    return null;
  }

}

function validateIP($env, $header) {
  return array_key_exists($header, $env) && filter_var($env[$header], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
};