package com.ozonehis.keycloak.magic.link.linkutils;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.function.Consumer;
import org.keycloak.authentication.AuthenticationFlowContext;
import static org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;

public class MagiclinkUtils {
    private static final String DEFAULT_USER_ID = "4b6f84da-040d-45ef-b68a-25c40f91f7e8";

    private static final String DEFAULT_USER_EMAIL = "jdoe@example.com";

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

    public static UserModel getOrCreate(KeycloakSession session, RealmModel realm, String email, boolean forceCreate) {
        UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, realm, email);
        if (user == null && forceCreate) {
            user = session.users().addUser(realm, email);
            user.setEnabled(true);
            user.setEmail(email);
        }

        return user;
    }

    public static String getAttemptedUsername(AuthenticationFlowContext context) {
        if (context.getUser() != null && context.getUser().getEmail() != null) {
            return context.getUser().getEmail();
        }
        String username =
                trimToNull(context.getAuthenticationSession().getAuthNote(ATTEMPTED_USERNAME));
        if (username != null) {
            if (isValidEmail(username)) {
                return username;
            }
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
            if (user != null && user.getEmail() != null) {
                return user.getEmail();
            }
        }
        return null;
    }

    private static UriBuilder actionTokenBuilder(URI baseUri, String tokenString, String clientId) {
        return Urls.realmBase(baseUri)
                .path(RealmsResource.class, "getLoginActionsService")
                .path(LoginActionsService.class, "executeActionToken")
                .queryParam("key", tokenString)
                .queryParam("client_id", clientId);
    }

    public static String trimToNull(final String s) {
        if (s == null) {
            return null;
        }
        String trimmed = s.trim();
        if ("".equalsIgnoreCase(trimmed)) trimmed = null;
        return trimmed;
    }

    public static boolean isValidEmail(String email) {
        try {
            InternetAddress a = new InternetAddress(email);
            a.validate();
            return true;
        } catch (AddressException e) {
            return false;
        }
    }
}
