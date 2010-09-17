package org.intalio.tempo.security.impl;

import java.rmi.RemoteException;

import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.rbac.RBACException;

public interface IOpenSSOTicketValidator {

	public String getTokenFromOpenSSOToken(String tokenId)
	throws AuthenticationException, RBACException, RemoteException;
	
	public void setTokenServiceImpl(TokenServiceImpl tokenServiceImpl);
	
}
