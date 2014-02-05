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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.intalio.tempo.security.Property;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OMParser {
    private static final Logger LOG = LoggerFactory.getLogger(OMParser.class);

    private OMElement _element;

    public OMParser(OMElement element) {
        _element = element;
        _element.build();
        if (_element.getParent() != null) _element.detach();
    }

    public String getRequiredString(QName parameter) throws IllegalArgumentException{
        OMElement e = _element.getFirstChildWithName(parameter);
        if (e == null)
            throw new IllegalArgumentException("Missing parameter: " + parameter);
        String text = e.getText();
        if (text == null || text.trim().length() == 0)
            throw new IllegalArgumentException("Empty parameter: " + parameter);
        if (LOG.isDebugEnabled())
            LOG.debug("Parameter " + parameter + ": " + text);
        return text;
    }

    public String[] getRequiredStringArray(QName parameter) throws IllegalArgumentException {
        Iterator<OMElement> itr = _element.getChildElements();
        ArrayList<String> textList = new ArrayList<String>();
        while (itr.hasNext()) {
            OMElement childElement = itr.next();
            if (childElement.getQName().equals(parameter)) {
                textList.add(childElement.getText());
            }
        }
        if (textList == null || textList.size() == 0)
            throw new IllegalArgumentException("Empty parameter: " + parameter);
        if (LOG.isDebugEnabled())
            LOG.debug("Parameter " + parameter + ": " + textList.toString());
        return textList.toArray(new String[textList.size()]);
    }

    public Property[] getProperties(QName parameter) throws IllegalArgumentException{
        OMElement e = _element.getFirstChildWithName(parameter);
        if (e == null)
            throw new IllegalArgumentException("Missing properties parameter: " + parameter);
        Iterator<OMElement> iter = e.getChildElements();
        ArrayList<Property> props = new ArrayList<Property>();
        while (iter.hasNext()) {
            OMElement prop = iter.next();
            OMElement name = prop.getFirstChildWithName(new QName(prop.getNamespace().getNamespaceURI(),"name"));
            if (name == null)
                throw new IllegalArgumentException("Missing property name: " + prop);
            OMElement value = prop.getFirstChildWithName(new QName(prop.getNamespace().getNamespaceURI(),"value"));
            if (value == null)
                throw new IllegalArgumentException("Missing property value: " + prop);
            props.add(new Property(name.getText(), value.getText()));
        }
        return props.toArray(new Property[props.size()]);
    }

    public Map<String,Property[]> getRequiredMapForAbstractType(QName parameter) {
        Iterator<OMElement> iter = _element.getChildrenWithName(parameter);
        Map<String,Property[]> abastractMap = new HashMap<String,Property[]>();
        while (iter.hasNext()) {
            OMElement abstractType = iter.next();
            OMElement id = abstractType.getFirstChildWithName(new QName(abstractType.getNamespace().getNamespaceURI(),"id"));
            if (id == null)
                throw new IllegalArgumentException("Missing property name: " + abstractType);
            OMElement realms = abstractType.getFirstChildWithName(new QName(abstractType.getNamespace().getNamespaceURI(),"realms"));
            if (realms == null)
                throw new IllegalArgumentException("Missing property name: " + abstractType);
            OMElement details = abstractType.getFirstChildWithName(new QName(abstractType.getNamespace().getNamespaceURI(),"details"));
            Iterator<OMElement> iterProp = details.getChildElements();
            ArrayList<Property> props = new ArrayList<Property>();
            while (iterProp.hasNext()) {
                OMElement prop = iterProp.next();
                OMElement name = prop.getFirstChildWithName(new QName(prop.getNamespace().getNamespaceURI(),"name"));
                if (name == null)
                    throw new IllegalArgumentException("Missing property name: " + prop);
                OMElement value = prop.getFirstChildWithName(new QName(prop.getNamespace().getNamespaceURI(),"value"));
                if (value == null)
                    throw new IllegalArgumentException("Missing property value: " + prop);
                props.add(new Property(name.getText(), value.getText()));
            }
            abastractMap.put(id.getText(), props.toArray(new Property[props.size()]));
        }
        return abastractMap;
    }

    public Map<String, Map<String, Property[]>> getRequiredRoleMap(QName role) {
        Map<String, Map<String, Property[]>> roles = new HashMap<String, Map<String, Property[]>>();

        Iterator<OMElement> itr = _element.getChildElements();

        while (itr.hasNext()) {
            OMElement roleElement = itr.next();
            if (roleElement.getQName().equals(role)) {
                Map<String, Property[]> roleProperties = new HashMap<String, Property[]>();
                OMElement roleNameElement = roleElement
                        .getFirstChildWithName(new QName(roleElement
                                .getNamespace().getNamespaceURI(), "name"));
                String roleName = roleNameElement.getText();

                Iterator<OMElement> userElements = roleElement
                        .getChildElements();
                while (userElements.hasNext()) {
                    OMElement userElement = userElements.next();
                    if (userElement.getQName().equals(RBACQueryConstants.USER)) {
                        OMElement userNameElement = userElement
                                .getFirstChildWithName(new QName(userElement
                                        .getNamespace().getNamespaceURI(),
                                        "name"));
                        String userName = userNameElement.getText();

                        Iterator<OMElement> iterProp = userElement
                                .getChildElements();
                        ArrayList<Property> props = new ArrayList<Property>();
                        while (iterProp.hasNext()) {
                            OMElement prop = iterProp.next();

                            if (prop.getQName().equals(
                                    new QName(prop.getNamespace()
                                            .getNamespaceURI(), "property"))) {
                                OMElement name = prop
                                        .getFirstChildWithName(new QName(prop
                                                .getNamespace()
                                                .getNamespaceURI(), "name"));
                                if (name == null)
                                    throw new IllegalArgumentException(
                                            "Missing property name: " + prop);
                                OMElement value = prop
                                        .getFirstChildWithName(new QName(prop
                                                .getNamespace()
                                                .getNamespaceURI(), "value"));
                                if (value == null)
                                    throw new IllegalArgumentException(
                                            "Missing property value: " + prop);

                                props.add(new Property(name.getText(), value
                                        .getText()));
                            }
                        }

                        roleProperties.put(userName,
                                props.toArray(new Property[props.size()]));
                    }
                }

                roles.put(roleName, roleProperties);
            }
        }

        return roles;
    }
}
