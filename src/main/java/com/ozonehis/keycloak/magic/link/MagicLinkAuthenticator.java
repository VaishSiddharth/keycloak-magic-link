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
        String token = MagiclinkUtils.generateMagicLink(context);

        // Uncomment if click here page is required
//        context.challenge(context.form().setAttribute("magicLink", token).createForm("send-email.ftl"));

        try {
            URI location= new URI(token);
            context.forceChallenge(Response.seeOther(location).build());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Handle the magic link verification
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
