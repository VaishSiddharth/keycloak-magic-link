package com.ozonehis.keycloak.magic.link;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class MagiclinkUtils {

    private static final String OPENMRS_USER_ROLE = "System Developer";

    private static final String OPENMRS_CLIENT_ID = "14b6083d-2d3c-4fb1-a75d-0f5af17be198";

    public static UserModel createUser(KeycloakSession session, RealmModel realm) {
        String firstName = MagicConstants.FIRST_NAMES[randomNumberGenerator(MagicConstants.FIRST_NAMES.length)];
        String lastName = MagicConstants.LAST_NAMES[randomNumberGenerator(MagicConstants.LAST_NAMES.length)];
        String username = firstName + randomNumberGenerator(9999) + lastName;
        String email = username + "@example.com";

        UserModel user = session.users().addUser(realm, username);
        user.setEnabled(true);
        user.setEmailVerified(true);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.grantRole(session.roles().getClientRole(realm.getClientById(OPENMRS_CLIENT_ID), OPENMRS_USER_ROLE));

        return user;
    }

    private static int randomNumberGenerator(int to) {
        return (int) (Math.random() * to) + 1;
    }
}
