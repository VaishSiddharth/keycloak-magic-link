package com.ozonehis.keycloak.magic.link.linkutils;

import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;

public class MagiclinkUtils {
    private static final String DEFAULT_USER_ID = "4b6f84da-040d-45ef-b68a-25c40f91f7e8";

    private static final String DEFAULT_USER_EMAIL = "jdoe@example.com";

    public static String generateMagicLink(AuthenticationFlowContext context) {

        int tokenExpiration = 600; // 10 minutes
        KeycloakSession session = context.getSession();

        int absoluteExpirationInSecs = Time.currentTime() + tokenExpiration;
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        MagicLinkActionToken token = new MagicLinkActionToken(DEFAULT_USER_ID, absoluteExpirationInSecs, DEFAULT_USER_EMAIL,
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
}
