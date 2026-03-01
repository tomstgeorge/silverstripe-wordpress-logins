<?php

namespace TomStGeorge\SilverStripeWordpressLogins\Controller;

use TomStGeorge\SilverStripeWordpressLogins\Service\TokenService;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Security\Security;

class AuthController extends Controller
{
    private static $url_segment = 'silverstripe-auth';

    private static $allowed_actions = [
        'index',
        'verify',
        'upsert',
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        return $this->jsonResponse([
            'success' => false,
            'error' => 'Specify /silverstripe-auth/verify or /silverstripe-auth/upsert',
        ], 400);
    }

    public function verify(HTTPRequest $request): HTTPResponse
    {
        if (!$this->checkSharedSecret($request)) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Forbidden',
            ], 403);
        }

        if (!$request->isPOST()) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'POST required',
            ], 405);
        }

        $data = $this->getRequestData($request);
        $email = isset($data['email']) ? trim(mb_strtolower((string) $data['email'])) : '';
        $password = isset($data['password']) ? (string) $data['password'] : '';

        if ($email === '' || $password === '') {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Missing email or password',
            ], 400);
        }

        /** @var Member|null $member */
        $member = Member::get()->filter('Email', $email)->first();
        if (!$member || !$member->exists()) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Invalid credentials',
            ], 200);
        }

        /** @var MemberAuthenticator $authenticator */
        $authenticator = Injector::inst()->get(MemberAuthenticator::class);

        $result = null;
        $validation = $authenticator->checkPassword($member, $password, $result);

        if (!$validation || !$validation->isValid()) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Invalid credentials',
            ], 200);
        }

        return $this->jsonResponse([
            'success' => true,
            'email' => $member->Email,
            'first_name' => $member->FirstName,
            'last_name' => $member->Surname,
        ]);
    }

    public function upsert(HTTPRequest $request): HTTPResponse
    {
        if (!$this->checkSharedSecret($request)) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Forbidden',
            ], 403);
        }

        if (!$request->isPOST()) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'POST required',
            ], 405);
        }

        $data = $this->getRequestData($request);
        $email = isset($data['email']) ? trim(mb_strtolower((string) $data['email'])) : '';
        $password = isset($data['password']) ? (string) $data['password'] : '';
        $firstName = isset($data['first_name']) ? trim((string) $data['first_name']) : null;
        $lastName = isset($data['last_name']) ? trim((string) $data['last_name']) : null;

        if ($email === '' || $password === '') {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Missing email or password',
            ], 400);
        }

        /** @var Member|null $member */
        $member = Member::get()->filter('Email', $email)->first();
        if (!$member) {
            $member = Member::create();
            $member->Email = $email;
        }

        if ($firstName !== null && $firstName !== '') {
            $member->FirstName = $firstName;
        }
        if ($lastName !== null && $lastName !== '') {
            $member->Surname = $lastName;
        }

        $result = $member->changePassword($password);
        if (!$result || !$result->isValid()) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Password did not meet requirements',
            ], 400);
        }

        // Ensure the member can log in.
        if (!$member->canLogin()) {
            return $this->jsonResponse([
                'success' => false,
                'error' => 'Member cannot log in',
            ], 400);
        }

        return $this->jsonResponse([
            'success' => true,
            'email' => $member->Email,
            'first_name' => $member->FirstName,
            'last_name' => $member->Surname,
        ]);
    }

    /**
     * Very small informational endpoint to check wiring and current user.
     */
    public function ping(HTTPRequest $request): HTTPResponse
    {
        $current = Security::getCurrentUser();
        return $this->jsonResponse([
            'success' => true,
            'current_user' => $current ? [
                'id' => $current->ID,
                'email' => $current->Email,
            ] : null,
        ]);
    }

    protected function checkSharedSecret(HTTPRequest $request): bool
    {
        $secret = Environment::getEnv('SILVERSTRIPE_INTERNAL_AUTH_SHARED_SECRET')
            ?: Environment::getEnv('SILVERSTRIPE_DUAL_LOGIN_SHARED_SECRET');

        if (!$secret) {
            return false;
        }

        $header = (string) $request->getHeader('X-SilverStripe-Internal-Auth');
        if ($header === '') {
            return false;
        }

        return hash_equals($secret, $header);
    }

    /**
     * Accept JSON or form-encoded payloads.
     *
     * @return array<string,mixed>
     */
    protected function getRequestData(HTTPRequest $request): array
    {
        $contentType = (string) $request->getHeader('Content-Type');
        if (stripos($contentType, 'application/json') !== false) {
            $raw = $request->getBody();
            $data = json_decode((string) $raw, true);
            if (is_array($data)) {
                return $data;
            }
        }

        return $request->postVars() ?? [];
    }

    protected function jsonResponse(array $data, int $status = 200): HTTPResponse
    {
        $response = HTTPResponse::create();
        $response->setStatusCode($status);
        $response->addHeader('Content-Type', 'application/json; charset=utf-8');
        $response->setBody(json_encode($data));
        return $response;
    }
}

