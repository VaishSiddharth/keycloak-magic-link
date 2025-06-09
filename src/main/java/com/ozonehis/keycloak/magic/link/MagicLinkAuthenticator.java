package com.ozonehis.keycloak.magic.link;

import com.ozonehis.keycloak.magic.link.linkutils.MagiclinkUtils;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class MagicLinkAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Create user automatically
        UserModel user = MagiclinkUtils.createUser(context.getSession(), context.getRealm());
        
        // Set the user in the context
        context.setUser(user);
        
        // Get the original redirect URI
        String redirectUri = context.getAuthenticationSession().getRedirectUri();
        
        // Complete the authentication
        context.success();
        
        // Redirect back to the client application
        if (redirectUri != null) {
            try {
                context.getSession().getContext().getUri().getRequestUriBuilder()
                    .replacePath(redirectUri)
                    .build();
            } catch (Exception e) {
                throw new RuntimeException("Failed to redirect to client application", e);
            }
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No action needed as we're handling everything in authenticate
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true; // Adjust as necessary for your requirements
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Set required actions if necessary
    }

    @Override
    public void close() {
        // Cleanup resources if needed
    }
}
