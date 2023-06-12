<?php

namespace Hslavich\OneloginSamlBundle\Controller;

use Hslavich\OneloginSamlBundle\Event\LoginEvent;
use Hslavich\OneloginSamlBundle\Security\Firewall\SamlListener;
use Hslavich\OneloginSamlBundle\Security\Utils\OneLoginAuthRegistry;
use InvalidArgumentException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\HttpFoundation\Request;

class SamlController extends AbstractController
{
    /**
     * @var OneLoginAuthRegistry
     */
    private $authRegistry;

    public function __construct(OneLoginAuthRegistry $authRegistry)
    {
        $this->authRegistry = $authRegistry;
    }

    public function loginAction(Request $request, EventDispatcherInterface $dispatcher, $idp = null)
    {
        $session = $request->getSession();
        $authErrorKey = Security::AUTHENTICATION_ERROR;

        if ($request->attributes->has($authErrorKey)) {
            $error = $request->attributes->get($authErrorKey);
        } elseif (null !== $session && $session->has($authErrorKey)) {
            $error = $session->get($authErrorKey);
            $session->remove($authErrorKey);
        } else {
            $error = null;
        }

        if ($error) {
            throw new \RuntimeException($error->getMessage());
        }

        if ($request->query->has('redirect_uri')) {
            $redirectUri = $request->query->get('redirect_uri');
        } else {
            $redirectUri = $session->get('_security.main.target_path');
        }

        // Don't redirect to the login page to avoid potential loops
        if (strpos($redirectUri, $request->getPathInfo()) !== false)  {
            $redirectUri = null;
        }

        $dispatcher->dispatch(new LoginEvent($request, $idp), LoginEvent::PRE_LOGIN_ACTION);

        $this->authRegistry->getIdpAuth($idp)->login($redirectUri);
    }

    public function metadataAction($idp = null)
    {
        try {
            $auth = $this->authRegistry->getIdpAuth($idp);
        } catch (InvalidArgumentException $e) {
            throw new NotFoundHttpException(sprintf('IDP %s not found', $idp), $e);
        }

        $metadata = $auth->getSettings()->getSPMetadata();

        $response = new Response($metadata);
        $response->headers->set('Content-Type', 'xml');

        return $response;
    }

    public function assertionConsumerServiceAction()
    {
        throw new \RuntimeException('You must configure the check path to be handled by the firewall.');
    }

    public function singleLogoutServiceAction()
    {
        throw new \RuntimeException('You must activate the logout in your security firewall configuration.');
    }
}
