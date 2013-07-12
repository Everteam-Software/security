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

import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.ServiceClient;
import org.intalio.tempo.security.Property;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.intalio.bpms.common.AxisUtil;

/**
 * RBACAdminService client.
 */
public class RBACAdminClient {

    /**
     * logger for RBACAdminClient.
     */
    private Logger logger = LoggerFactory.getLogger(RBACAdminClient.class);
    /**
     * endpoint url for RBACAdminService.
     */

    private String endpoint;
    /**
     * httpChunking property.
     */
    private String httpChunking = "false";

    /**
     * Create a RBACAdmin service client.
     * 
     * @param endpointUrl endpoint of the RBACAdmin service
     */
    public RBACAdminClient(final String endpointUrl) {
        endpoint = endpointUrl;
    }

    /**
     * get endpoint url for RBACAdminService.
     * @return endpoint String
     */
    public final String getEndpoint() {
        return endpoint;
    }

    /**
     * call operation getUserProperties.
     * @param realm String
     * @param user String
     * @return properties Property[]
     * @throws AxisFault service Exception
     */
    public final Property[] getUserProperties(final String realm,
            final String user) throws AxisFault {
        OMElement request = element(RBACAdminConstants.GET_PROPERTIES);
        request.addChild(elementText(RBACAdminConstants.ROLE, "null"));
        request.addChild(elementText(RBACAdminConstants.USER, user));
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        OMParser response = invoke(
                RBACAdminConstants.GET_PROPERTIES.getLocalPart(), request);
        return response.getProperties(RBACAdminConstants.DETAILS);
    }

    /**
     * call operation getUserProperties.
     * @param realm String
     * @param role String
     * @return properties Property[]
     * @throws AxisFault service Exception
     */
    public final Property[] getRoleProperties(final String realm,
            final String role) throws AxisFault {
        OMElement request = element(RBACAdminConstants.GET_PROPERTIES);
        request.addChild(elementText(RBACAdminConstants.ROLE, role));
        request.addChild(elementText(RBACAdminConstants.USER, "null"));
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        OMParser response = invoke(
                RBACAdminConstants.GET_PROPERTIES.getLocalPart(), request);
        return response.getProperties(RBACAdminConstants.DETAILS);
    }

    /**
     * call operation getRoles.
     * @return roleProperties Map<String, Property[]>
     * @throws AxisFault service Exception
     */
    public final Map<String, Property[]> getRoles() throws AxisFault {
        OMElement request = elementText(RBACAdminConstants.GET_ROLES, "");
        OMParser response = invoke(RBACAdminConstants.GET_ROLES.getLocalPart(),
                request);
        return response
                .getRequiredMapForAbstractType(RBACAdminConstants.ROLE_TYPE);
    }

    /**
     * call operation getUsers.
     * @return usersProperties Map<String, Property[]>
     * @throws AxisFault service Exception
     */
    public final Map<String, Property[]> getUsers() throws AxisFault {
        OMElement request = elementText(RBACAdminConstants.GET_USERS, "");
        OMParser response = invoke(RBACAdminConstants.GET_USERS.getLocalPart(),
                request);
        return response
                .getRequiredMapForAbstractType(RBACAdminConstants.USER_TYPE);
    }

    /**
     * call operation getAttributes.
     * @param forObject String
     * @return attributes String[]
     * @throws AxisFault  service Exception
     */
    public final String[] getAttributes(final String forObject)
            throws AxisFault {
        OMElement request = element(RBACAdminConstants.GET_ATTRIBUTES);
        request.addChild(elementText(RBACAdminConstants.OBJECT, forObject));
        OMParser response = invoke(
                RBACAdminConstants.GET_ATTRIBUTES.getLocalPart(), request);
        return response.getRequiredStringArray(RBACAdminConstants.ATTRIBUTE);
    }

    /**
     * call operation getRealms.
     * @return realms String[]
     * @throws AxisFault service Exception
     */
    public final String[] getRealms() throws AxisFault {
        OMElement request = elementText(RBACAdminConstants.GET_REALMS, "");
        OMParser response = invoke(
                RBACAdminConstants.GET_REALMS.getLocalPart(), request);
        return response.getRequiredStringArray(RBACAdminConstants.REALM);
    }

    /**
     * call operation addUser.
     * @param user String
     * @param realm String
     * @param properties Property[]
     * @return token String
     * @throws AxisFault service Exception
     */
    public final String addUser(final String user, final String realm,
            final Property[] properties) throws AxisFault {
        OMElement request = getUserRequestElement(user, properties);
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        request.addChild(elementText(RBACAdminConstants.ACTION,
                RBACAdminConstants.ADD_ACTION));
        OMParser response = invoke(
                RBACAdminConstants.MODIFY_USER.getLocalPart(), request);

        return response.getRequiredString(RBACAdminConstants.TOKEN);
    }

    /**
     * call operation editUser.
     * @param user String
     * @param realm String
     * @param properties Property[]
     * @return token String
     * @throws AxisFault service Exception
     */
    public final String editUser(final String user, final String realm,
            final Property[] properties) throws AxisFault {
        OMElement request = getUserRequestElement(user, properties);
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        request.addChild(elementText(RBACAdminConstants.ACTION,
                RBACAdminConstants.EDIT_ACTION));
        OMParser response = invoke(
                RBACAdminConstants.MODIFY_USER.getLocalPart(), request);

        return response.getRequiredString(RBACAdminConstants.TOKEN);
    }

    /**
     * call operation deleteUser.
     * @param user String
     * @param realm String
     * @return token String
     * @throws AxisFault service Exception
     */
    public final String deleteUser(final String user, final String realm)
            throws AxisFault {
        OMElement request = element(RBACAdminConstants.MODIFY_USER);
        request.addChild(elementText(RBACAdminConstants.USER, user));
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        request.addChild(elementText(RBACAdminConstants.ACTION,
                RBACAdminConstants.DELETE_ACTION));
        OMParser response = invoke(
                RBACAdminConstants.MODIFY_USER.getLocalPart(), request);

        return response.getRequiredString(RBACAdminConstants.TOKEN);
    }

    /**
     * call operation addRole.
     * @param role String
     * @param realm String
     * @param properties Property[]
     * @return token String
     * @throws AxisFault service Exception
     */
    public final String addRole(final String role, final String realm,
            final Property[] properties) throws AxisFault {
        OMElement request = getRoleRequestElement(role, properties);
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        request.addChild(elementText(RBACAdminConstants.ACTION,
                RBACAdminConstants.ADD_ACTION));
        OMParser response = invoke(
                RBACAdminConstants.MODIFY_ROLE.getLocalPart(), request);

        return response.getRequiredString(RBACAdminConstants.TOKEN);
    }

    /**
     * call operation editRole.
     * @param role String
     * @param realm String
     * @param properties Property[]
     * @return token String
     * @throws AxisFault service Exception
     */
    public final String editRole(final String role, final String realm,
            final Property[] properties) throws AxisFault {
        OMElement request = getRoleRequestElement(role, properties);
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        request.addChild(elementText(RBACAdminConstants.ACTION,
                RBACAdminConstants.EDIT_ACTION));
        OMParser response = invoke(
                RBACAdminConstants.MODIFY_ROLE.getLocalPart(), request);

        return response.getRequiredString(RBACAdminConstants.TOKEN);
    }

    /**
     * call operation deleteRole.
     * @param role String
     * @param realm String
     * @return token String
     * @throws AxisFault service Exception
     */
    public final String deleteRole(final String role, final String realm)
            throws AxisFault {
        OMElement request = element(RBACAdminConstants.MODIFY_ROLE);
        request.addChild(elementText(RBACAdminConstants.ROLE, role));
        request.addChild(elementText(RBACAdminConstants.REALM, realm));
        request.addChild(elementText(RBACAdminConstants.ACTION,
                RBACAdminConstants.DELETE_ACTION));
        OMParser response = invoke(
                RBACAdminConstants.MODIFY_ROLE.getLocalPart(), request);

        return response.getRequiredString(RBACAdminConstants.TOKEN);
    }

    /**
     * invoke operation.
     * @param action String
     * @param request OMElement
     * @return response OMParser
     * @throws AxisFault service Exception
     */
    protected final OMParser invoke(final String action,
                final OMElement request) throws AxisFault {
        ServiceClient serviceClient = null;
        OMElement response = null;
        AxisUtil util = new AxisUtil();
        try {
            serviceClient = util.getServiceClient();
            serviceClient.getOptions().setTo(new EndpointReference(endpoint));
            serviceClient.getOptions().setAction(action);
            // Disabling chunking as lighthttpd doesnt support it
            if (isChunking()) {
                serviceClient.getOptions().setProperty(
                        org.apache.axis2.transport.http.HTTPConstants.CHUNKED,
                        Boolean.FALSE);
            } else {
                serviceClient.getOptions().setProperty(
                        org.apache.axis2.transport.http.HTTPConstants.CHUNKED,
                        Boolean.FALSE);
            }
            response = serviceClient.sendReceive(request);
            response.build();
        } catch (AxisFault e) {
            logger.error("Service was called with this option "
                    + serviceClient.getServiceContext());
            e.printStackTrace();
            throw e;
        } finally {
            if (serviceClient != null) {
                try {
                    util.closeClient(serviceClient);
                } catch (Exception e) {
                    logger.error("Error while cleanup");
                }
            }
        }
        logger.debug("Invoked service for authentication");
        return new OMParser(response);
    }

    /**
     * create User Request Element.
     * @param user String
     * @param properties Property[]
     * @return userRequestElement OMElement
     */
    private static OMElement getUserRequestElement(final String user,
            final Property[] properties) {
        OMElement request = element(RBACAdminConstants.MODIFY_USER);
        request.addChild(elementText(RBACAdminConstants.USER, user));
        OMElement requestDetail = element(RBACAdminConstants.DETAILS);
        for (Property prop : properties) {
            requestDetail.addChild(elementProperty(prop.getName(), prop
                    .getValue().toString()));
        }
        request.addChild(requestDetail);
        return request;
    }

    /**
     * create Role Request Element.
     * @param role String
     * @param properties Property[]
     * @return roleRequestElement OMElement
     */
    private static OMElement getRoleRequestElement(final String role,
            final Property[] properties) {
        OMElement request = element(RBACAdminConstants.MODIFY_ROLE);
        request.addChild(elementText(RBACAdminConstants.ROLE, role));
        OMElement requestDetail = element(RBACAdminConstants.DETAILS);
        for (Property prop : properties) {
            requestDetail.addChild(elementProperty(prop.getName(), prop
                    .getValue().toString()));
        }
        request.addChild(requestDetail);
        return request;
    }

    /**
     * create element Property.
     * @param name String
     * @param value String
     * @return elementProperty OMElement
     */
    private static OMElement elementProperty(final String name,
            final String value) {
        OMElement prop = element(RBACAdminConstants.PROPERTY);
        prop.addChild(elementText(RBACAdminConstants.NAME, name));
        prop.addChild(elementText(RBACAdminConstants.VALUE, value));
        return prop;
    }

    /**
     * create element.
     * @param name QName
     * @return element OMElement
     */
    private static OMElement element(final QName name) {
        return OM_FACTORY.createOMElement(name);
    }

    /**
     * create elementText.
     * @param name QName
     * @param text String
     * @return element OMElement
     */
    private static OMElement elementText(final QName name,
            final String text) {
        OMElement element = OM_FACTORY.createOMElement(name);
        element.setText(text);
        return element;
    }

    /**
     * set httpChunking.
     * @param chunking String
     */
    public final void setHttpChunking(final String chunking) {
        this.httpChunking = chunking;
    }

    /**
     * get httpChunking.
     * @return httpChunking boolean
     */
    public final boolean isChunking() {
        return Boolean.parseBoolean(this.httpChunking);
    }
}
