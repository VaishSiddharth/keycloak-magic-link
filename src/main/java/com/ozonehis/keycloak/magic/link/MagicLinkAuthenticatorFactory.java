package com.ozonehis.keycloak.magic.link;

import static com.ozonehis.keycloak.magic.link.MagicLink.setupDefaultFlow;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderEvent;


public class MagicLinkAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "magiclink-authenticator";
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();


    @Override
    public Authenticator create(KeycloakSession session) {
        return new MagicLinkAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(
                (ProviderEvent ev) -> {
                    if (ev instanceof RealmModel.RealmPostCreateEvent event) {
                        setupDefaultFlow(event.getKeycloakSession(), event.getCreatedRealm());
                    }
                });
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Authenticator for Magic Link";
    }

    @Override
    public String getDisplayType() {
        return "Magic Link Authenticator";
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{Requirement.REQUIRED};
    }

    @Override
    public String getReferenceCategory() {
        return "Magic Link";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
