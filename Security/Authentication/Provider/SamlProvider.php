<?php

namespace Hslavich\OneloginSamlBundle\Security\Authentication\Provider;

use Doctrine\ORM\EntityManagerInterface;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlToken;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenFactoryInterface;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenInterface;
use Hslavich\OneloginSamlBundle\Security\User\SamlUserFactoryInterface;
use Hslavich\OneloginSamlBundle\Security\User\SamlUserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticatorManagerInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class SamlProvider extends AbstractAuthenticator implements AuthenticatorInterface//AuthenticationProviderInterface
{
    protected $userProvider;

    /**
     * @var SamlUserFactoryInterface
     */
    protected $userFactory;

    /**
     * @var SamlTokenFactoryInterface
     */
    protected $tokenFactory;

    /**
     * @var EntityManagerInterface
     */
    protected $entityManager;
    protected $options = [];

    protected AuthenticatorManagerInterface $authenticatorManager;

    protected AuthenticationSuccessHandlerInterface $successHandler;
    protected AuthenticationFailureHandlerInterface $failureHandler;

    public function setUserProvider(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    public function setPersistUser(bool $persistUser)
    {
        $this->options = array_merge(array(
            'persist_user' => $persistUser
        ), $this->options);
    }

    public function setUserFactory(SamlUserFactoryInterface $userFactory)
    {
        $this->userFactory = $userFactory;
    }

    public function setTokenFactory(SamlTokenFactoryInterface $tokenFactory)
    {
        $this->tokenFactory = $tokenFactory;
    }

    public function setEntityManager($entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function setAuthenticatorManager(AuthenticatorManagerInterface $authenticatorManager): void
    {
        $this->authenticatorManager = $authenticatorManager;
    }

    public function setSuccessHandler(AuthenticationSuccessHandlerInterface $successHandler): void
    {
        $this->successHandler = $successHandler;
    }

    public function setFailureHandler(AuthenticationFailureHandlerInterface $failureHandler): void
    {
        $this->failureHandler = $failureHandler;
    }

    /**
     * @param Request $request
     */
    public function authenticate(Request $request): Passport
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
        //
        $user = $this->retrieveUser($token);

        if ($user) {
            if ($user instanceof SamlUserInterface) {
                $user->setSamlAttributes($token->getAttributes());
            }

            $this->checkUser($user, $token);

            $authenticatedToken = $this->tokenFactory->createToken(
                $user,
                $token->getAttributes(),
                $this->getRoles($user),
                $token->getIdpName()
            );
            $authenticatedToken->setAuthenticated(true);

            $userBadge = new UserBadge($username, function (string $username) {
                return $this->entityManager->getRepository(UserInterface::class)->findOneBy(['username' => $username]);
            });

            return new SelfValidatingPassport($userBadge);
            //return $authenticatedToken;
        }

        throw new AuthenticationException('The authentication failed.');
    }

    public function getRoles(SamlUserInterface $user)
    {
        return $user->getRoles();
    }

    public function supports(Request $request): ?bool
    {
        return $this->authenticatorManager->supports($request);
        //return $token instanceof SamlTokenInterface;
    }

    /**
     * @param SamlTokenInterface $token
     */
    protected function retrieveUser($token)
    {
        try {
            return $this->userProvider->loadUserByUsername($token->getUsername(), $token->getIdpName());
        } catch (UsernameNotFoundException $e) {
            if ($this->userFactory instanceof SamlUserFactoryInterface) {
                return $this->generateUser($token);
            }

            throw $e;
        }
    }

    protected function generateUser($token)
    {
        $user = $this->userFactory->createUser($token);

        if ($this->options['persist_user'] && $this->entityManager) {
            $this->entityManager->persist($user);
            $this->entityManager->flush();
        }

        return $user;
    }

    protected function checkUser(SamlUserInterface $user, TokenInterface $token)
    {
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return $this->successHandler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }
}
