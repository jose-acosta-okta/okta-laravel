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
        //$response->expires_in;
        //$response->scope;
        //$response->access_token;
        //$response->id_token;
        //dd($response);
        if(!isset($response->access_token)) {
            die('Could not exchange code for an access token');
        }

        $token = $response->access_token;

        return redirect()->route('home', compact('response'));
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
