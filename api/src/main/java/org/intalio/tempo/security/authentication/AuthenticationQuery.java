/**
 * Copyright (C) 2003, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package org.intalio.tempo.security.authentication;

import java.rmi.Remote;
import java.rmi.RemoteException;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.rbac.RBACException;

/**
 * Administrative review services for performing queries on users of the
 * authentication system.
 *
 * @author <a href="http://www.intalio.com">&copy; Intalio Inc.</a>
 */
public interface AuthenticationQuery
    extends Remote
{

    /**
     * Get a user's credentials.
     * <p>
     * This is valid only if the user exists.
     * <p>
     * Note that this method may not be relevance for all provider.
     *
     * @param user identifier of the user
     * @return plugin-specific set of credentials for the user
     */
    public Property[] getUserCredentials( String user )
        throws AuthenticationException, RemoteException;

    /**
     * Get a user's credentials.
     * <p>
     * Returns true if user is a Workflow Admin user or a member of Worflow Admin Roles, false otherwise.
     * <p>
	 *
     * @param user identifier of the user
     * @return true if user is a Workflow Admin user , otherwise false.
     */
	public boolean isWorkflowAdmin(String user)throws AuthenticationException, RemoteException, RBACException;
    
}
