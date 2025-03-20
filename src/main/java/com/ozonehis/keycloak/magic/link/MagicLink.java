package com.ozonehis.keycloak.magic.link;

import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderFactory;

@Slf4j
public class MagicLink {

    public static final String MAGIC_LINK_AUTH_FLOW_ALIAS = "magic link";
    public static final String COOKIE_PROVIDER_ID =
            org.keycloak.authentication.authenticators.browser.CookieAuthenticatorFactory.PROVIDER_ID;
    public static final String IDP_REDIRECTOR_PROVIDER_ID =
            org.keycloak.authentication.authenticators.browser.IdentityProviderAuthenticatorFactory
                    .PROVIDER_ID;
    public static final String MAGIC_LINK_PROVIDER_ID = MagicLinkAuthenticatorFactory.PROVIDER_ID;

    public static void setupDefaultFlow(KeycloakSession session, RealmModel realm) {
        AuthenticationFlowModel flow = realm.getFlowByAlias(MAGIC_LINK_AUTH_FLOW_ALIAS);
        if (flow != null) {
            log.info("{} flow exists. Skipping.", MAGIC_LINK_AUTH_FLOW_ALIAS);
            return;
        }

        log.info("creating built-in auth flow for {}", MAGIC_LINK_AUTH_FLOW_ALIAS);
        flow = new AuthenticationFlowModel();
        flow.setAlias(MAGIC_LINK_AUTH_FLOW_ALIAS);
        flow.setBuiltIn(true);
        flow.setProviderId("basic-flow");
        flow.setDescription("Magic link authentication");
        flow.setTopLevel(true);
        flow = realm.addAuthenticationFlow(flow);

//        realm.setBrowserFlow(flow);

        // cookie
        addExecutionToFlow(
                session,
                realm,
                flow,
                COOKIE_PROVIDER_ID,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE);
        // kerberos?
        // identity provider redirector
        addExecutionToFlow(
                session,
                realm,
                flow,
                IDP_REDIRECTOR_PROVIDER_ID,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE);

        // forms
        AuthenticationFlowModel forms = new AuthenticationFlowModel();
        forms.setAlias(String.format("%s %s", MAGIC_LINK_AUTH_FLOW_ALIAS, "forms"));
        forms.setProviderId("basic-flow");
        forms.setDescription("Forms for magic link authentication flow.");
        forms.setTopLevel(false);
        forms = realm.addAuthenticationFlow(forms);

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setParentFlow(flow.getId());
        execution.setFlowId(forms.getId());
        execution.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE);
        execution.setAuthenticatorFlow(true);
        execution.setPriority(getNextPriority(realm, flow));
        execution = realm.addAuthenticatorExecution(execution);

        addExecutionToFlow(
                session,
                realm,
                forms,
                MAGIC_LINK_PROVIDER_ID,
                AuthenticationExecutionModel.Requirement.REQUIRED);
    }

    private static int getNextPriority(RealmModel realm, AuthenticationFlowModel parentFlow) {
        List<AuthenticationExecutionModel> executions =
                realm.getAuthenticationExecutionsStream(parentFlow.getId()).collect(Collectors.toList());
        return executions.isEmpty() ? 0 : executions.get(executions.size() - 1).getPriority() + 1;
    }


    private static void addExecutionToFlow(
            KeycloakSession session,
            RealmModel realm,
            AuthenticationFlowModel flow,
            String providerId,
            AuthenticationExecutionModel.Requirement requirement) {
        boolean hasExecution =
                realm
                        .getAuthenticationExecutionsStream(flow.getId())
                        .filter(e -> providerId.equals(e.getAuthenticator()))
                        .count()
                        > 0;

        if (!hasExecution) {
            log.info("adding execution {} for auth flow for {}", providerId, flow.getAlias());
            ProviderFactory f =
                    session.getKeycloakSessionFactory().getProviderFactory(Authenticator.class, providerId);
            AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
            execution.setParentFlow(flow.getId());
            execution.setRequirement(requirement);
            execution.setAuthenticatorFlow(false);
            execution.setAuthenticator(providerId);
            execution = realm.addAuthenticatorExecution(execution);
        }
    }
}
