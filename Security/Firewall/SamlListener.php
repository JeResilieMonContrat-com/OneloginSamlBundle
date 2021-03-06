<?php

namespace Hslavich\OneloginSamlBundle\Security\Firewall;

use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlToken;
use Hslavich\OneloginSamlBundle\Security\Utils\OneLoginAuthRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;

class SamlListener extends AbstractAuthenticationListener
{
    /**
     * @var OneLoginAuthRegistry
     */
    private $authRegistry;

    /**
     * @var string
     */
    private $defaultIdpName;

    public function setAuthRegistry(OneLoginAuthRegistry $authRegistry)
    {
        $this->authRegistry = $authRegistry;
    }

    public function setDefaultIdpName(string $defaultIdpName)
    {
        $this->defaultIdpName = $defaultIdpName;
    }

    /**
     * Performs authentication.
     *
     * @param Request $request A Request instance
     * @return TokenInterface|Response|null The authenticated token, null if full authentication is not possible, or a Response
     *
     * @throws AuthenticationException if the authentication fails
     * @throws \Exception if attribute set by "username_attribute" option not found
     */
    protected function attemptAuthentication(Request $request)
    {
        $idpName = $this->options['idp_name'];
        $oneLoginAuth = $this->authRegistry->getIdpAuth($idpName);

        $oneLoginAuth->processResponse();
        if ($oneLoginAuth->getErrors()) {
            $this->logger->error($oneLoginAuth->getLastErrorReason());
            throw new AuthenticationException($oneLoginAuth->getLastErrorReason());
        }

        if (isset($this->options['use_attribute_friendly_name']) && $this->options['use_attribute_friendly_name']) {
            $attributes = $oneLoginAuth->getAttributesWithFriendlyName();
        } else {
            $attributes = $oneLoginAuth->getAttributes();
        }
        $attributes['sessionIndex'] = $oneLoginAuth->getSessionIndex();
        $token = new SamlToken();
        $token->setAttributes($attributes);
        $token->setIdpName($idpName);

        if (isset($this->options['username_attribute'])) {
            if (!array_key_exists($this->options['username_attribute'], $attributes)) {
                $this->logger->error(sprintf("Found attributes: %s", print_r($attributes, true)));
                throw new \Exception(sprintf("Attribute '%s' not found in SAML data", $this->options['username_attribute']));
            }

            $username = $attributes[$this->options['username_attribute']][0];
        } else {
            $username = $oneLoginAuth->getNameId();
            $token->setNameId($username);
        }
        $token->setUser($username);

        return $this->authenticationManager->authenticate($token);
    }
}
