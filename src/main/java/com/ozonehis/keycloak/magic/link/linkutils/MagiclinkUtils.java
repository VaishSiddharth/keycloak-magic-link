package com.ozonehis.keycloak.magic.link.linkutils;

import com.ozonehis.keycloak.magic.link.MagicConstants;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;

public class MagiclinkUtils {

    public static String generateMagicLink(AuthenticationFlowContext context, UserModel user) {

        int tokenExpiration = 600; // 10 minutes
        KeycloakSession session = context.getSession();

        int absoluteExpirationInSecs = Time.currentTime() + tokenExpiration;
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        MagicLinkActionToken token = new MagicLinkActionToken(user.getId(), absoluteExpirationInSecs, user.getEmail(),
                session.getContext().getClient().getClientId(), authenticationSession.getRedirectUri());

        UriInfo uriInfo = session.getContext().getUri();
        RealmModel realm = session.getContext().getRealm();

        UriBuilder builder = actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo), token.getIssuedFor());

        session.getContext().setRealm(realm);
        return builder.build(realm.getName()).toString();
    }

    private static UriBuilder actionTokenBuilder(URI baseUri, String tokenString, String clientId) {
        return Urls.realmBase(baseUri)
                .path(RealmsResource.class, "getLoginActionsService")
                .path(LoginActionsService.class, "executeActionToken")
                .queryParam("key", tokenString)
                .queryParam("client_id", clientId);
    }

    public static UserModel createUser(KeycloakSession session, RealmModel realm) {
        String firstName = MagicConstants.FIRST_NAMES[randomNumberGenerator(MagicConstants.FIRST_NAMES.length)];
        String lastName = MagicConstants.LAST_NAMES[randomNumberGenerator(MagicConstants.LAST_NAMES.length)];
        String username = firstName + randomNumberGenerator(9999) + lastName;
        String email = username + "@example.com";

        UserModel user = session.users().addUser(realm, username);
        user.setEnabled(true);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.grantRole(session.roles().getClientRole(realm.getClientById("14b6083d-2d3c-4fb1-a75d-0f5af17be198"), "System Developer"));

        return user;
    }

    private static int randomNumberGenerator(int to) {
        return (int) (Math.random() * to) + 1;
    }
}
