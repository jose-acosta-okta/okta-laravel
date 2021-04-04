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
        $id_token = $request->id_token;
        $access_token = $request->access_token;
        $expires_in = $request->expires_in;

        $jwt_id_token = $this->okta->getProfile($id_token);
        //dd($jwt_id_token);
        $jwt_access_token = $this->okta->getProfile($access_token);
        dd($jwt_access_token);

        //dd($response['access_token']);
        return view('pages.home', compact('access_token','id_token'));
    }

}
