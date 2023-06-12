<?php

namespace Hslavich\OneloginSamlBundle\Event;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\EventDispatcher\Event;

class LoginEvent extends Event
{
    private Request $request;
    private ?string $idp;

    public const PRE_LOGIN_ACTION = 'hslavich.saml.login.pre';

    public function __construct(Request $request, ?string $idp = null)
    {
        $this->request = $request;
        $this->idp = $idp;
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function getIdp(): ?string
    {
        return $this->idp;
    }
}
