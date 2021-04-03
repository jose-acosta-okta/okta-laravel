<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use GuzzleHttp\Client;
use App\Http\Controllers\UsernamePasswordToken;
use Okta\Hooks\RegistrationInlineHook;
use Exception;
use Okta\JwtVerifier\Adaptors\SpomkyLabsJose;

class OktaController extends Controller
{
    private $clientId;
    private $clientSecret;
    private $redirectUri;
    private $metadataUrl;
    private $apiToken;
    private $apiUrlBase;

    public function __construct()
    {
        $this->clientId     = env('OKTA_CLIENT_ID');
        $this->clientSecret = env('OKTA_CLIENT_SECRET');
        $this->redirectUri  = env('OKTA_REDIRECT_URI');
        $this->metadataUrl  = env('OKTA_METADATA_URL');
        $this->apiToken     = env('OKTA_API_TOKEN');
        $this->apiUrlBase   = env('OKTA_API_URL_BASE');
        $this->issuer   = env('OKTA_ISSUER');

    }

    public function index()
    {
        return $this->getAllUsers();
    }

    public function login()
    {
        $baseUrlParts = parse_url($this->issuer);

        return $baseUrlParts;
    }


    function getCode($code)
    {
        $authHeaderSecret = base64_encode( env('OKTA_CLIENT_ID') . ':' . env('OKTA_CLIENT_SECRET') );
        $query = http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => env('APP_URL').'/authorization-code/callback'
        ]);

        $headers = [
            'Authorization: Basic ' . $authHeaderSecret,
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded',
            'Connection: close',
            'Content-Length: 0'
        ];

        $url = env("OKTA_ISSUER").'/v1/token?' . $query;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POST, 1);
        $output = curl_exec($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if(curl_error($ch)) {
            $httpcode = 500;
        }
        curl_close($ch);
        return json_decode($output);
    }

    public function validateHookRegistration(){
        try {
            $hook = new RegistrationInlineHook();


            $hook->allowUser(FALSE);
            //$hook->changeProfileAttribute('company','Picard Financial');
            //$hook->changeProfileAttribute('managerId','38337373');
            //$hook->changeProfileAttribute('accountManagerId','1093938383');
            return $hook->display();
        } catch (Exception $e) {
            return $e->getMessage();
        }
    }

    public function buildAuthorizeUrl($state)
    {
        $metadata = $this->httpRequest($this->metadataUrl);

        $url = $metadata->authorization_endpoint . '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $state,
        ]);
        return $url;
    }

    public function buildRegistrationAuthorizeUrl($state)
    {
        $metadata = $this->httpRequest($this->metadataUrl);
       // dd($metadata);
        $url = $metadata->registration_endpoint . '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $state,
        ]);
        return $url;
    }

    public function authorizeUser()
    {
        if (session('state') != $_GET['state']) {
            $result['error'] = true;
            $result['errorMessage'] = 'Authorization server returned an invalid state parameter';
            return $result;
        }

        if (isset($_GET['error'])) {
            $result['error'] = true;
            $result['errorMessage'] = 'Authorization server returned an error: '.htmlspecialchars($_GET['error']);
            return $result;
        }

        $metadata = $this->httpRequest($this->metadataUrl);

        $response = $this->httpRequest($metadata->token_endpoint, [
            'grant_type' => 'authorization_code',
            'code' => $_GET['code'],
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ]);

        if (! isset($response->access_token)) {
            $result['error'] = true;
            $result['errorMessage'] = 'Error fetching access token!';
            return $result;
        }
        $_SESSION['access_token'] = $response->access_token;

        // verify the token at the token introspection endpoint
        $token = $this->httpRequest($metadata->introspection_endpoint, [
            'token' => $response->access_token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ]);

        if ($token->active == 1) {
            $_SESSION['username'] = $token->username;
            $this->fillUserDetails($token->username);
            $result['success'] = true;
            return $result;
        }
    }

    public function handleRegistrationPost($input)
    {
        //if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            $input = [
                'first_name'      => $input['first_name'],
                'last_name'       => $input['last_name'],
                'email'           => $input['email']
            ];

            // local form validation
            $this->validateRegistrationForm($input);
            if ($this->errors) {
                $viewData = [
                    'input' => $input,
                    'errors' => $this->errors,
                    'errorMessage' => $this->errorMessage
                ];
                view('register', $viewData);
                return true;
            }

            // if local validation passes, attempt to register the user
            // via the Okta API
            $result = $this->oktaApi->registerUser($input);
            $result = json_decode($result, true);
            if (isset($result['errorCode'])) {
                $viewData = [
                    'input' => $input,
                    'errors' => true,
                    'errorMessage' => '<br>(Okta) ' . $result['errorCauses'][0]['errorSummary']
                ];
                view('register', $viewData);
                return true;
            }
            return true;
        //}

        header('HTTP/1.0 405 Method Not Allowed');
        die();
    }

    private function validateRegistrationForm($input)
    {
        $errorMessage = '';
        $errors = false;

        // validate field lengths
        if (strlen($input['first_name']) > 50) {
            $errorMessage .= "<br>'First Name' is too long (50 characters max)!";
            $errors = true;
        }
        if (strlen($input['last_name']) > 50) {
            $errorMessage .= "<br>'Last Name' is too long (50 characters max)!";
            $errors = true;
        }
        if (strlen($input['email']) > 100) {
            $errorMessage .= "<br>'Email' is too long (100 characters max)!";
            $errors = true;
        }
        if (strlen($input['password']) > 72) {
            $errorMessage .= "<br>'Password' is too long (72 characters max)!";
            $errors = true;
        }
        if (strlen($input['password']) < 8) {
            $errorMessage .= "<br>'Password' is too short (8 characters min)!";
            $errors = true;
        }

        // validate field contents
        if (empty($input['first_name'])) {
            $errorMessage .= "<br>'First Name' is required!";
            $errors = true;
        }
        if (empty($input['last_name'])) {
            $errorMessage .= "<br>'Last Name' is required!";
            $errors = true;
        }
        if (empty($input['email'])) {
            $errorMessage .= "<br>'Email' is required!";
            $errors = true;
        } else if (! filter_var($input['email'], FILTER_VALIDATE_EMAIL)) {
            $errorMessage .= "<br>Invalid email!";
            $errors = true;
        }
        if (empty($input['password'])) {
            $errorMessage .= "<br>'Password' is required!";
            $errors = true;
        }
        if (empty($input['repeat_password'])) {
            $errorMessage .= "<br>'Repeat Password' is required!";
            $errors = true;
        }
        if ($input['password'] !== $input['repeat_password']) {
            $errorMessage .= "<br>Passwords do not match!";
            $errors = true;
        }

        $this->errors = $errors;
        $this->errorMessage = $errorMessage;
    }

    public function registerUser($input)
    {
        $data['profile'] = [
            'firstName' => $input['first_name'],
            'lastName'  => $input['last_name'],
            'email'     => $input['email'],
            'login'     => $input['email']
        ];
        $data['credentials'] = [
            'password'  => [
                'value' => $input['password']
            ]
        ];
        $data = json_encode($data);

        $ch = curl_init($this->apiUrlBase . 'users');
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data),
            'Authorization: SSWS ' . $this->apiToken
        ]);

        return curl_exec($ch);
    }

    public function fillUserDetails($username)
    {
        $userData = json_decode($this->findUser(['email' => $username]), true);
        $userId = $userData[0]['id'];

        $users = json_decode($this->getUsers(), true);
        $userList = [];
        foreach($users as $user) {
            $userList[$user['id']] = $user['profile']['firstName'];
        }

        $userGroups = json_decode($this->getUserGroups($userId), true);
        $groupList = [];
        foreach($userGroups as $group) {
            $groupList[$group['id']] = $group['profile']['name'];
        }

        $userRoles = json_decode($this->getUserRoles($userId), true);
        $roleList = [];
        foreach($userRoles as $role) {
            $roleList[$role['id']] = $role['type'];
        }

        $_SESSION['username'] = $username;
        $_SESSION['id'] = $userId;
        $_SESSION['users'] = json_decode($this->getUsers(), true);
        $_SESSION['groups'] = $groupList;
        $_SESSION['roles'] = $roleList;
    }

    public function getMe()
    {
        $url = $this->apiUrlBase . 'users/me';

        return $this->oktaApiGet($url);
    }

    public function findUser($input)
    {
        $url = $this->apiUrlBase . 'users?q=' . urlencode($input) . '&limit=1';

        return $this->oktaApiGet($url);
    }

    public function deactivateUser($userId)
    {
        $url = $this->apiUrlBase . 'users/' . $userId . '/lifecycle/deactivate';

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, []);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/json',
            'Authorization: SSWS ' . $this->apiToken
        ]);

        return curl_exec($ch);
    }

    public function getAllUsers()
    {
        $url = $this->apiUrlBase . 'users/?limit=25';

        return $this->oktaApiGet($url);
    }

    public function getUserGroups($userId)
    {
        $url = $this->apiUrlBase . 'users/' . $userId . '/groups';

        return $this->oktaApiGet($url);
    }

    public function getAllGroups()
    {
        $url = $this->apiUrlBase . '/groups?filter=type%20eq%20%22OKTA_GROUP%22';

        return $this->oktaApiGet($url);
    }

    public function getGroupUsers($groupId)
    {
        $url = $this->apiUrlBase . 'groups/'. $groupId .'/users';
        return $this->oktaApiGet($url);
    }

    public function addGroupUsers($groupId,$userId)
    {
        $url = $this->apiUrlBase . 'groups/'. $groupId . '/users' . '/'. $userId;

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_setopt($ch, CURLOPT_POSTFIELDS, []);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/json',
            'Authorization: SSWS ' . $this->apiToken
        ]);

        return curl_exec($ch);
    }

    public function getProfile($access_token)
    {
        dd(env('OKTA_CLIENT_ID'));

        $jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
            //->setAdaptor(new \Okta\JwtVerifier\Adaptors\SpomkyLabsJose())
            ->setIssuer(env('OKTA_ISSUER'))
            ->setAudience('api://default')
            ->setClientId(env('OKTA_CLIENT_ID'))
            ->build();

        $jwt = $jwtVerifier->verify($access_token);

        return $jwt->claims;

    }

    public function getUserRoles($userId)
    {
        $url = $this->apiUrlBase . 'users/' . $userId . '/roles';

        return $this->oktaApiGet($url);
    }

    private function oktaApiGet($url)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/json',
            'Authorization: SSWS ' . $this->apiToken
        ]);

        return curl_exec($ch);
    }

    public function resetPassword($userId)
    {
        $url = $this->apiUrlBase . 'users/' . $userId . '/lifecycle/reset_password';

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, []);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/json',
            'Authorization: SSWS ' . $this->apiToken
        ]);

        return curl_exec($ch);
    }

    private function httpRequest($url, $params = null)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if ($params) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        }
        return json_decode(curl_exec($ch));
    }

    function verifyJwt($jwt)
    {
        try {
            $jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
                ->setIssuer(getenv('OKTA_ISSUER'))
                ->setAudience('api://default')
                ->setClientId(getenv('OKTA_CLIENT_ID'))
                ->build();

            return $jwtVerifier->verify($jwt);
        } catch (\Exception $e) {
            return false;
        }
    }
}
