<?php namespace Dtkahl\Auth;

use Dtkahl\ArrayTools\Map;
use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;

class AuthMiddleware {

  /** @var Map */
  private $_options;

  /**
   * @param array $options
   */
  public function __construct(array $options = [])
  {
    $this->_options = new Map($options);
  }

  /**
   * @param Request $request
   * @param Response $response
   * @param App $app
   * @return Response
   */
  public function __invoke(Request $request, Response $response, App $app)
  {
    /**
     * @var Auth $auth
     */
    $container      = $app->getContainer();
    $auth           = $container->get($this->_options->get("auth_container", "auth"));

    $auth->configure($this->_options, $container);
    $auth->validateSession();

    return $app($request, $response);
  }

}