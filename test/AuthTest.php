<?php namespace Dtkahl\AuthTest;

use Dtkahl\Auth\Auth;
use Dtkahl\Auth\AuthMiddleware;
use Interop\Container\ContainerInterface;
use Slim\App;
use Slim\Http\Cookies;
use Slim\Http\Headers;
use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Stream;
use Slim\Http\Uri;

class AuthTest extends \PHPUnit_Framework_TestCase
{

    /** @var TestUser[] */
    private $users = [];

    /** @var App $app */
    private $app;

    /** @var AuthMiddleware $middleware */
    private $middleware;

    public function setUp()
    {
        $this->app = new App();
        $container = $this->app->getContainer();

        /*
         * set container
         */

        $container['request'] = function () {
            $headers = new Headers();
            return new Request(
                'GET',
                new Uri('http', '127.0.0.1'),
                $headers,
                ["session_token" => 'ba57473e9d0b7199c28772f1309cca72'],
                [],
                new Stream(fopen("php://temp/", "r+"))
            );
        };

        $container['response'] = function () {
            return new Response();
        };

        $container['cookies'] = function (ContainerInterface $c) {
            /** @var Request $request */
            $request = $c->get('request');
            return new Cookies($request->getCookieParams());
        };

        $container['auth'] = function () {
            return new Auth();
        };

        /*
         * configure middleware
         */

        $this->middleware = new AuthMiddleware($container, [

            "salt" => "usB05FJc.U9VLtYhZInebp",

            "handleLogin" => function ($email, $hash) {
                if ($email == "test@test.com" && $hash == '$2a$08$usB05FJc.U9VLtYhZInebeTrLQmyV56uwptHW0qBBBuGAydEIRKo.') {
                    return $this->users[] = new TestUser();
                }
                return null;
            },

            "retrieveUser" => function ($remember_token) {
                foreach ($this->users as $user) {
                    if ($user->retrieveRememberToken() == $remember_token) {
                        return $user;
                    }
                }
                return null;
            }
        ]);
    }

    public function testMiddlewareNoValidCookie()
    {
        /**
         * @var Auth $auth
         * @var Request $request
         * @var Response $response
         */
        $container = $this->app->getContainer();
        $auth = $container->get("auth");
        $request = $container->get('request');
        $response = $container->get('response');
        $middleware = $this->middleware;

        $middleware($request, $response, $this->app);

        $this->assertNull($auth->getUser());
        $this->assertFalse($auth->isAuthenticated());

        $user = new TestUser();
        $user->storeRememberToken('$2a$08$usB05FJc.U9VLtYhZInebeAIOh2oJZ/TnMhVoERg6EYw4ApTgvyWu');
        $this->users[] = $user;

        $auth->validateSession();

        $this->assertInstanceOf(TestUser::class, $auth->getUser());
        $this->assertTrue($auth->isAuthenticated());
    }

    public function testMiddlewareValidCookie()
    {
        /**
         * @var Auth $auth
         * @var Request $request
         * @var Response $response
         */
        $container = $this->app->getContainer();
        $auth = $container->get("auth");
        $request = $container->get('request');
        $response = $container->get('response');
        $middleware = $this->middleware;

        $middleware($request, $response, $this->app);

        $this->assertNull($auth->getUser());
        $this->assertFalse($auth->isAuthenticated());
    }

    public function testLoginLogout()
    {
        /**
         * @var Auth $auth
         * @var Request $request
         * @var Response $response
         */
        $container = $this->app->getContainer();
        $auth = $container->get("auth");
        $request = $container->get('request');
        $response = $container->get('response');
        $middleware = $this->middleware;

        $middleware($request, $response, $this->app);

        /** @var Response $response */
        $response = $auth->login($response, "wrong@mail.com", "wrongpw");
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEmpty($response->getHeaders());
        $this->assertNull($auth->getUser());
        $this->assertFalse($auth->isAuthenticated());

        /** @var Response $response */
        $response = $auth->login($response, "test@test.com", "test1234");
        $this->assertInstanceOf(Response::class, $response);
        $this->assertArrayHasKey("Set-Cookie", $response->getHeaders());
        $this->assertInstanceOf(TestUser::class, $auth->getUser());
        $this->assertTrue($auth->isAuthenticated());

        /** @var Response $response */
        $response = $auth->logout($response);
        $this->assertInstanceOf(Response::class, $response);
        $this->assertArrayHasKey("Set-Cookie", $response->getHeaders());
        $this->assertNull($auth->getUser());
        $this->assertFalse($auth->isAuthenticated());
    }

}