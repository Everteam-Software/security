/**
 * Copyright (C) 2003-2008, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package org.intalio.tempo.security.impl.openssoiplanet;

import java.rmi.RemoteException;

import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.impl.IOpenSSOTicketValidator;
import org.intalio.tempo.security.impl.TokenServiceImpl;
import org.intalio.tempo.security.rbac.RBACException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;

/**
 * Default OpenSSO integration.
 */
public class DefaultIPlanetOpenSSOTicketValidator implements IOpenSSOTicketValidator {
    Logger _logger = LoggerFactory.getLogger(TokenServiceImpl.class);
    TokenServiceImpl tokenServiceImpl;

    public void setTokenServiceImpl(TokenServiceImpl tokenServiceImpl) {
    	this.tokenServiceImpl = tokenServiceImpl;
    }
    
    public String getTokenFromOpenSSOToken(String tokenId)
    throws AuthenticationException, RBACException, RemoteException {
	    try {
	        SSOTokenManager tokenManager = SSOTokenManager.getInstance();
	        SSOToken token = tokenManager.createSSOToken(
	                        tokenId);
	        if (token == null) {
	                throw new AuthenticationException(
	                                "Failed to get the sso token with token ID: " + tokenId);
	        }
	
	        // check the token validity
	        SSOTokenManager manager = tokenManager;
	        if (!manager.isValidToken(token)) {
	                throw new AuthenticationException("Token with ID: " + tokenId
	                                + " is invalid.");
	        }
	
	        // get the user with sso token
	        AMIdentity userIdentity = IdUtils.getIdentity(token);
	        String user = userIdentity.getName();
	
	        return tokenServiceImpl.createToken(user);
	    } catch (Exception e) {
	        _logger.error("OpenSSO Token Error",e);
	        throw new AuthenticationException("Authentication failed! OpenSSO ticket authentication failed!");
	    }
	}
	
}
