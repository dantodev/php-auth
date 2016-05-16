<?php namespace Dtkahl\Auth;

use Dtkahl\ArrayTools\Map;
use Slim\App;
use Slim\Container;
use Slim\Http\Request;
use Slim\Http\Response;

class AuthMiddleware {

  /** @var Map */
  private $_options;

  /** @var Container */
  private $_container;

  /**
   * @param $container
   * @param array $options
   */
  public function __construct($container, array $options = [])
  {
    $this->_options = new Map($options);
    $this->_container = $container;
  }

  /**
   * @param Request $request
   * @param Response $response
   * @param callable $app
   * @return Response
   */
  public function __invoke(Request $request, Response $response, callable $app)
  {
    /**
     * @var Auth $auth
     */
    $auth = $this->_container->get($this->_options->get("auth_container", "auth"));

    $auth->configure($this->_container, $this->_options);
    $auth->validateSession();

    return $app($request, $response);
  }

}