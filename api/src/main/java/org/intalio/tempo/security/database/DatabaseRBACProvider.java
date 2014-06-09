/**
 * Copyright (C) 2014, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package org.intalio.tempo.security.database;

import org.intalio.tempo.security.database.dao.DAO;
import org.intalio.tempo.security.rbac.RBACAdmin;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RBACQuery;
import org.intalio.tempo.security.rbac.RBACRuntime;
import org.intalio.tempo.security.rbac.provider.RBACProvider;

public class DatabaseRBACProvider implements RBACProvider {

    private RBACAdmin admin;
    private RBACQuery query;
    private RBACRuntime runtime;

    /**
     * @param realmName
     * @param dao
     */
    public DatabaseRBACProvider(String realmName, DAO dao) {
        admin = new DatabaseRBACAdmin(realmName, dao);
        query = new DatabaseRBACQuery(realmName, dao);
        runtime = new DatabaseRBACRuntime(realmName, dao);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.provider.RBACProvider#getAdmin()
     */
    public RBACAdmin getAdmin() throws RBACException {
        return admin;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.provider.RBACProvider#getQuery()
     */
    public RBACQuery getQuery() throws RBACException {

        return query;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.provider.RBACProvider#getRuntime()
     */
    public RBACRuntime getRuntime() throws RBACException {

        return runtime;
    }

}
