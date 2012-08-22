/**
 * Copyright (c) 2005-2007 Intalio inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * Intalio inc. - initial API and implementation
 */

package org.intalio.tempo.security.ws;

import static org.intalio.tempo.security.ws.Constants.OM_FACTORY;

import java.rmi.RemoteException;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.HttpClient;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.token.TokenService;
import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.intalio.bpms.common.AxisUtil;

/**
 * Client web services API for the Token Service.
 */
public class TokenClient implements TokenService {

	Logger _logger = LoggerFactory.getLogger(TokenClient.class);
	String _endpoint;
	private String httpChunking = "false";

 	/**
	 * Create a token service client
	 * 
	 * @param endpointUrl
	 *            endpoint of the token service
	 */
	public TokenClient(String endpointUrl) {
		_endpoint = endpointUrl;
	}

	public String getEndpoint() {
		return _endpoint;
	}

	public String authenticateUser(String user, String password)
			throws AuthenticationException, RBACException, RemoteException {
		OMElement request = element(TokenConstants.AUTHENTICATE_USER);
		request.addChild(elementText(TokenConstants.USER, user));
		BasicTextEncryptor encryptor = new BasicTextEncryptor();
		// time to encrypt before sending
		encryptor
				.setPassword(org.intalio.tempo.security.ws.Constants.PASSWORD_MASK);
		request.addChild(elementText(TokenConstants.PASSWORD,
				encryptor.encrypt(password)));

		OMParser response = invoke(
				TokenConstants.AUTHENTICATE_ENCRYPTED_USER.getLocalPart(), request);
		return response.getRequiredString(TokenConstants.TOKEN);
	}

	public String authenticateUser(String user, Property[] credentials)
			throws AuthenticationException, RBACException, RemoteException {
		OMElement request = element(TokenConstants.AUTHENTICATE_USER_WITH_CREDENTIALS);
		request.addChild(elementText(TokenConstants.USER, user));
		OMElement requestCred = element(TokenConstants.CREDENTIALS);
		for (int i = 0; i < credentials.length; i++) {
			OMElement prop = element(Constants.PROPERTY);
			prop.addChild(elementText(Constants.NAME, credentials[i].getName()));
			prop.addChild(elementText(Constants.VALUE, credentials[i]
					.getValue().toString()));
			requestCred.addChild(prop);
		}
		request.addChild(requestCred);
		OMParser response = invoke(
				TokenConstants.AUTHENTICATE_USER_WITH_CREDENTIALS
						.getLocalPart(),
				request);
		return response.getRequiredString(TokenConstants.TOKEN);
	}

	public Property[] getTokenProperties(String token)
			throws AuthenticationException, RemoteException {
		OMElement request = element(TokenConstants.GET_TOKEN_PROPERTIES);
		request.addChild(elementText(TokenConstants.TOKEN, token));
		OMParser response = invoke(
				TokenConstants.GET_TOKEN_PROPERTIES.getLocalPart(), request);
		return response.getProperties(Constants.PROPERTIES);
	}


    public boolean isWorkflowAdmin(String token) throws AuthenticationException, RemoteException {
        OMElement request = element(TokenConstants.IS_WORKFLOW_ADMIN);
        request.addChild(elementText(TokenConstants.TOKEN, token));
        OMParser response = invoke(TokenConstants.IS_WORKFLOW_ADMIN.getLocalPart(), request);
        
        return Boolean.valueOf(response.getRequiredString(TokenConstants.IS_WORKFLOW_ADMIN));
    }
    
    protected OMParser invoke(String action, OMElement request) throws AxisFault {
        ServiceClient serviceClient = null;
        OMElement response = null;
        AxisUtil util = new AxisUtil();
        try {
            serviceClient = util.getServiceClient();
            serviceClient.getOptions().setTo(new EndpointReference(_endpoint));
            serviceClient.getOptions().setAction(action);
            // Disabling chunking as lighthttpd doesnt support it
            if (isChunking())
                serviceClient.getOptions()
                        .setProperty(org.apache.axis2.transport.http.HTTPConstants.CHUNKED, Boolean.FALSE);
            else
                serviceClient.getOptions()
                        .setProperty(org.apache.axis2.transport.http.HTTPConstants.CHUNKED, Boolean.FALSE);
            response = serviceClient.sendReceive(request);
            response.build();
        } catch (AxisFault e) {
            _logger.error("Service was called with this option " + serviceClient.getServiceContext());
            throw e;
        } finally {
            if (serviceClient != null)
                try {
                    util.closeClient(serviceClient);
                } catch (Exception e) {
                    _logger.error("Error while cleanup");
                }
        }
        _logger.debug("Invoked service for authentication");
        return new OMParser(response);
    }


	private static OMElement element(QName name) {
		return OM_FACTORY.createOMElement(name);
	}

	private static OMElement elementText(QName name, String text) {
		OMElement element = OM_FACTORY.createOMElement(name);
		element.setText(text);
		return element;
	}

	public String getTokenFromTicket(String ticket, String serviceURL)
			throws AuthenticationException, RBACException, RemoteException {
		OMElement request = element(TokenConstants.PROXY_TICKET);
		request.addChild(elementText(TokenConstants.TICKET, ticket));
		request.addChild(elementText(TokenConstants.SERVICE_URL, serviceURL));
		OMParser response = invoke(
				TokenConstants.GETTOKEN_FROMTICKET.getLocalPart(), request);
		return response.getRequiredString(TokenConstants.TOKEN);
	}

	public String getTokenFromOpenSSOToken(String tokenId)
			throws AuthenticationException, RBACException, RemoteException {
		OMElement request = element(TokenConstants.OPENSSO_TICKET);
		request.addChild(elementText(TokenConstants.OPENSSO_TOKEN, tokenId));
		OMParser response = invoke(
				TokenConstants.GETTOKEN_FROM_OPSSSOTOKEN.getLocalPart(),
				request);
		return response.getRequiredString(TokenConstants.TOKEN);
	}

	public String getHttpChunking() {
		return httpChunking;
	}

	public void setHttpChunking(String httpChunking) {
		this.httpChunking = httpChunking;
	}
	
	public boolean isChunking() {
		return Boolean.parseBoolean(this.httpChunking);
	}
}
