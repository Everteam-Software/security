/**
 * Copyright (C) 2003, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package org.intalio.tempo.security.simple;

import java.rmi.RemoteException;
import java.util.Set;

import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationConstants;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.authentication.AuthenticationQuery;
import org.intalio.tempo.security.authentication.UserNotFoundException;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RBACQuery;
import org.intalio.tempo.security.rbac.provider.RBACProvider;
import org.intalio.tempo.security.util.IdentifierUtils;

/**
 * Simple implementation of the authentication query functions.
 *
 * @author <a href="boisvert@intalio.com">Alex Boisvert</a>
 */
class SimpleAuthenticationQuery
    implements AuthenticationQuery
{

    private SimpleSecurityProvider _provider;
    
    /** 
     * Construct simple authentication query functions.
     */
    SimpleAuthenticationQuery( String realm, SimpleSecurityProvider provider ) 
    {
        _provider = provider;
    }

    
    // implement AuthenticationQuery interface
    public Property[] getUserCredentials( String user )
        throws AuthenticationException
    {
        SimpleUser  simpleUser;
        Property    password;
		SimpleDatabase database;
        
		database = _provider.getDatabase();
        
        simpleUser = database.getUser( user );
        if ( simpleUser == null ) {
            throw new UserNotFoundException( "User not found: " + user );
        }
        
        password = new Property( AuthenticationConstants.PROPERTY_PASSWORD, 
                                 simpleUser.getPassword() );
        
        return new Property[] { password };
    }


	@Override
	public boolean isWorkflowAdmin(String identifier) throws AuthenticationException,
			RemoteException, RBACException {
		
		String realm = IdentifierUtils.getRealm( identifier );					
		RBACProvider rbac = _provider.getRBACProvider( realm );
		if ( rbac == null ) {
			throw new RBACException( 
				"SecurityProvider '" + _provider.getName()
				+ "' doesn't provide RBACProvider "
				+ "for realm '" + realm + "'" );
		}
		RBACQuery query = rbac.getQuery();
		if ( query == null ) {
			throw new RBACException( "RBACProvider doesn't provide RBACQuery" );
		}
		String[] roles=query.authorizedRoles(identifier);
		Set<String> workflowAdminRoles=_provider.getWorkflowAdminRoles();
		Set<String> workflowAdminUsers=_provider.getWorkflowAdminUsers();		
		boolean isAdmin=false;
		for(int i=0; i<roles.length;i++){
			isAdmin=workflowAdminRoles.contains(roles[i]);
			if(isAdmin) break;
			
		}		

		return (isAdmin || workflowAdminUsers.contains(identifier));
	}
    
}
