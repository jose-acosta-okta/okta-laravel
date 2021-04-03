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
        //dd('dd'. $access_token);
        //dd($id_token);
        //$access_token = $response['access_token'];
        //$id_token = $response['id_token'];
        //$token_expires_in = $response['expires_in'];
        $test = $this->okta->getProfile($access_token);
        //dd($test);
        //$jwtBuilder = new JwtVerifierBuilder();
        //$jwtBuilder->setIssuer(env('OKTA_ISSUER'));
        //$jwtBuilder->setAudience('api://default');
        //$jwtBuilder->setClientId(env('OKTA_CLIENT_ID'));
        //$jwtBuilder->build();
        //dd($jwtBuilder);
        /*
        $jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
            ->setIssuer(env('OKTA_ISSUER'))
            ->setAudience('api://default')
            ->setClientId(env('OKTA_CLIENT_ID'))
            ->build();

        $jwt = $jwtVerifier->verify($access_token);
        dd($jwt);
        */
        //$token = JWTAuth::getToken();
        //$token = $response['access_token'];
        //$payload = JWTAuth::decode($token);
        //dd($payload);
        //$apy = JWTAuth::getPayload($token)->toArray();
        //dd($apy);
        // JWK::parseKeySet($jwks) returns an associative array of **kid** to private
        // key. Pass this as the second parameter to JWT::decode.
        //JWT::decode($payload, JWK::parseKeySet($jwks), $supportedAlgorithm);


        //dd($response['access_token']);
        return view('pages.home', compact('access_token','id_token'));
    }

}
