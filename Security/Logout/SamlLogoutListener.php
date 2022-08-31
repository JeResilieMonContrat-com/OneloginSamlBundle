<?php

declare(strict_types=1);

namespace Hslavich\OneloginSamlBundle\Security\Logout;

use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenInterface;
use Hslavich\OneloginSamlBundle\Security\Utils\OneLoginAuthRegistry;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class SamlLogoutListener
{
    protected $samlAuth;

    public function __construct(OneLoginAuthRegistry $samlAuth)
    {
        $this->samlAuth = $samlAuth;
    }

    public function __invoke(LogoutEvent $event)
    {
        $token = $event->getToken();
        if (!$token instanceof SamlTokenInterface) {
            return;
        }

        $auth = $this->samlAuth->getIdpAuth($token->getIdpName());

        try {
            $auth->processSLO();
        } catch (\OneLogin\Saml2\Error $e) {
            if (!empty($auth->getSLOurl())) {
                $sessionIndex = $token->hasAttribute('sessionIndex') ? $token->getAttribute('sessionIndex') : null;
                $auth->logout(null, array(), $token->getUsername(), $sessionIndex);
            }
        }
    }
}
