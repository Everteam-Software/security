
/**
 * Copyright (C) 2014, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package org.intalio.tempo.security.database;

import org.intalio.tempo.security.authentication.AuthenticationAdmin;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.authentication.AuthenticationQuery;
import org.intalio.tempo.security.authentication.AuthenticationRuntime;
import org.intalio.tempo.security.authentication.provider.AuthenticationProvider;
import org.intalio.tempo.security.database.dao.DAO;

public class DatabaseAuthenticationProvider implements AuthenticationProvider {

    private String _realm;
    private DatabaseSecurityProvider _provider;
    private DAO _dao;

    /**
     * @param realmName
     * @param provider
     * @param dao
     */
    public DatabaseAuthenticationProvider(String realmName,
            DatabaseSecurityProvider provider, DAO dao) {
        _realm = realmName;
        _provider = provider;
        _dao = dao;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.authentication.provider.AuthenticationProvider
     * #getAdmin()
     */
    public AuthenticationAdmin getAdmin() throws AuthenticationException {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.authentication.provider.AuthenticationProvider
     * #getQuery()
     */
    public AuthenticationQuery getQuery() throws AuthenticationException {

        return new DatabaseAuthenticationQuery(_realm, _provider, _dao);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.authentication.provider.AuthenticationProvider
     * #getRuntime()
     */
    public AuthenticationRuntime getRuntime() throws AuthenticationException {

        return new DatabaseAuthenticationRunTime(_realm, _dao);
    }

}
