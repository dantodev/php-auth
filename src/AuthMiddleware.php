<?php namespace Dtkahl\Auth;

use Dtkahl\ArrayTools\Map;
use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;

class AuthMiddleware {

  private $_options;

  public function __construct(array $options = [])
  {
    $this->_options = new Map([
      'auth_container' => "auth",
      'cookies_container' => "cookies",
    ]);
    $this->_options->merge($options);

    $require = ["salt", "handleLogin", "retrieveUser"];
    if (!$this->_options->hasKeys($require)) {
      throw new \RuntimeException(sprintf("Auth Middleware require '%s' options.", implode("', '", $require)));
    }
  }

  public function __invoke(Request $request, Response $response, App $app)
  {
    /**
     * @var Auth $auth
     */
    $container      = $app->getContainer();
    $auth           = $container->get($this->_options->get("auth_container"));

    $auth->configure($this->_options, $container);
    $auth->validateSession();

    return $app($request, $response);
  }

}