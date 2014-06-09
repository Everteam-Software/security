/**
 * Copyright (C) 2014, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package org.intalio.tempo.security.database.util;

import org.intalio.tempo.security.impl.Realms;
import org.intalio.tempo.security.util.IdentifierUtils;

public class DatabaseHelperUtil {

    public static final char _separator = '\\';
    public static String _defaultrealm = "";
    public static final String ENCRYPTED_PASSWORD = "IntalioEncryptedpasswordForDatabase#123";

    /**
     * @param defaultrealm
     */
    public static void setdefaultrealm(String defaultrealm) {
        _defaultrealm = defaultrealm;
    }

    /**
     * @param identifier
     * @param realm
     * @return
     */
    public static String normalize(String identifier, String realm) {
        return IdentifierUtils.normalize(identifier, realm,
                Realms.isCaseSensitive(), _separator);
    }
}
