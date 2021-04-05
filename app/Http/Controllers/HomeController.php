<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\OktaApiService;
use Cookie;

class HomeController extends Controller
{
    public function __construct()
    {
        $this->clientId     = env('OKTA_CLIENT_ID');
        $this->clientSecret = env('OKTA_CLIENT_SECRET');
        $this->redirectUri  = env('OKTA_REDIRECT_URI');
        $this->metadataUrl  = env('OKTA_METADATA_URL');
        $this->apiToken     = env('OKTA_API_TOKEN');
        $this->apiUrlBase   = env('OKTA_API_URL_BASE');
        $this->issuer   = env('OKTA_ISSUER');
        $this->okta = new OktaController();
    }

    public function index(Request $request)
    {
        $expires_in = $request->expires_in;

        $isValid = $this->okta->verifyJwt($request->access_token);
        if ($isValid == true)
        {
            $id_token = $this->okta->parseJwt($request->id_token);
            $access_token = $this->okta->getProfile($request->access_token);
        } else
        {
            return redirect()->route('login');
        }
        //dd($access_token);
        return view('pages.home', compact('access_token','id_token'));
    }

}
