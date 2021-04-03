<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\OktaController;
use Illuminate\Http\Response;

class LoginController extends Controller
{
    private $okta;
    private $state = 'applicationState';

    public function __construct()
    {
        $this->okta = new OktaController();
    }

    public function index(Request $request)
    {

        return view('pages.login');
    }

    public function callback(Request $request)
    {

       //dd($request->code);
        $response = $this->okta->getCode($request->code);
        if(!isset($response->access_token))
        {
            die('Could not exchange code for an access token');
        }

        $access_token = $response->access_token;
        $id_token = $response->id_token;
        $expires_in = $response->expires_in;

        $minutes = 3600;
        $response = new Response('Set Cookie');
        $response->withCookie(cookie('access_token', $access_token, $minutes));

        $cookie = cookie('access_token', $access_token, true,$minutes);

        setcookie("access_token","$access_token",time()+$minutes,"/",false);
        //$response->expires_in;
        //$response->scope;
        //$response->access_token;
        //$response->id_token;
        //dd($response);

        //$token = $response;
        //dd($token);
        return redirect()->route('home', compact('id_token','access_token','expires_in'));
    }

    public function authCodeCallback(Request $request)
    {

       //dd($request->code);
        $response = $this->okta->getCode($request->code);
        //dd($response);
        if(!isset($response->access_token)) {
            die('Could not exchange code for an access token');
        }

        $token = $response->access_token;
        //dd($token);


        return redirect()->route('home');
    }
}
