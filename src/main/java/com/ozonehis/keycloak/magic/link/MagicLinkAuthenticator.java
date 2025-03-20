package com.ozonehis.keycloak.magic.link;

import com.ozonehis.keycloak.magic.link.linkutils.MagiclinkUtils;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.OptionalInt;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

public class MagicLinkAuthenticator extends UsernamePasswordForm {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        log.debug("MagicLinkAuthenticator.authenticate");
        String attemptedUsername = MagiclinkUtils.getAttemptedUsername(context);
        if (attemptedUsername == null) {
            super.authenticate(context);
        } else {
            log.debugf(
                    "Found attempted username %s from previous authenticator, skipping login form",
                    attemptedUsername);
            action(context);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        log.debug("MagicLinkAuthenticator.action");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String email = MagiclinkUtils.trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
        // check for empty email
        if (email == null) {
            // - first check for email from previous authenticator
            email = MagiclinkUtils.getAttemptedUsername(context);
        }
        log.debugf("email in action is %s", email);
        // - throw error if still empty
        if (email == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse =
                    challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        UserModel user =
                MagiclinkUtils.getOrCreate(
                        context.getSession(),
                        context.getRealm(),
                        email,
                        true);

        // check for no/invalid email address
        if (user == null
                || MagiclinkUtils.trimToNull(user.getEmail()) == null
                || !MagiclinkUtils.isValidEmail(user.getEmail())) {
            context
                    .getEvent()
                    .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
                    .event(EventType.LOGIN_ERROR)
                    .error(Errors.INVALID_EMAIL);
            context
                    .getAuthenticationSession()
                    .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
            return;
        }

        log.debugf("user is %s %s", user.getEmail(), user.isEnabled());

        // check for enabled user
        if (!enabledUser(context, user)) {
            return; // the enabledUser method sets the challenge
        }

        String token = MagiclinkUtils.generateMagicLink(context, user);

//         Uncomment if click here page is required
//        context.challenge(context.form().setAttribute("magicLink", token).createForm("send-email.ftl"));

        try {
            URI location = new URI(token);
            context.forceChallenge(Response.seeOther(location).build());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        log.infof("sent email to %s? Link? %s", user.getEmail(), token);
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

    @Override
    protected boolean validateForm(
            AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        log.debug("validateForm");
        return validateUser(context, formData);
    }

    @Override
    protected Response challenge(
            AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        log.debug("challenge");
        LoginFormsProvider forms = context.form();
        if (!formData.isEmpty()) forms.setFormData(formData);
        return forms.createLoginUsername();
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        log.debug("createLoginForm");
        return form.createLoginUsername();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        log.debug("getDefaultChallengeMessage");
        return context.getRealm().isLoginWithEmailAllowed()
                ? Messages.INVALID_USERNAME_OR_EMAIL
                : Messages.INVALID_USERNAME;
    }

}
