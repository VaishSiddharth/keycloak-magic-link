package com.ozonehis.keycloak.magic.link.linkutils;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;


public class MagicLinkActionTokenHandler extends AbstractActionTokenHandler<MagicLinkActionToken> {

    public MagicLinkActionTokenHandler() {
        super(
                MagicLinkActionToken.TOKEN_TYPE,
                MagicLinkActionToken.class,
                "invalidRequestMessage",
                EventType.EXECUTE_ACTION_TOKEN,
                Errors.INVALID_REQUEST);
    }

    @Override
    public AuthenticationSessionModel startFreshAuthenticationSession(
            MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
        return tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
    }

    @Override
    public Response handleToken(MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();

        final AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        user.setEmailVerified(true);

        String nextAction =
                AuthenticationManager.nextRequiredAction(
                        tokenContext.getSession(),
                        authSession,
                        tokenContext.getRequest(),
                        tokenContext.getEvent());
        return AuthenticationManager.redirectToRequiredActions(
                tokenContext.getSession(),
                tokenContext.getRealm(),
                authSession,
                tokenContext.getUriInfo(),
                nextAction);
    }
}
