package org.intalio.tempo.security.simple;

import java.io.FileOutputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Iterator;

import javax.xml.namespace.QName;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMDocument;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.rbac.RBACAdmin;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RoleNotFoundException;
import org.intalio.tempo.security.rbac.UserNotFoundException;
import org.intalio.tempo.security.util.IdentifierUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleRBACAdmin implements RBACAdmin {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleRBACAdmin.class);

    private SimpleSecurityProvider _securityProvider;
    private String _realm;
    private static final String USER = "user";
    private static final String ROLE = "role";
    private static final String PASSWORD = "password";

    public SimpleRBACAdmin(String realm, SimpleSecurityProvider simpleSecurityProvider) {
        _securityProvider = simpleSecurityProvider;
        _realm = realm;
    }

    @Override
    public void addUser(String user, Property[] properties) throws RBACException, RemoteException {
        OMDocument document = getDocumentElement();
        LOG.debug("got document object");
        addElement(USER, user, properties, document);
        LOG.debug("element added");
        try {
            updateConfigFile(document);
        } catch (RBACException e) {
            try {
                deleteRole(user);
            } catch (Exception ex) {
                LOG.error("Error occured while trying to rollback the changes", e);
            }
            throw e;
        }
    }

    @Override
    public void deleteUser(String user) throws RBACException, RemoteException {
        OMDocument document = deleteElement(USER, user);
        updateConfigFile(document);
    }

    @Override
    public void addRole(String role, Property[] properties) throws RoleNotFoundException, RBACException, RemoteException {
        OMDocument document = getDocumentElement();
        addElement(ROLE, role, properties, document);
        try {
            updateConfigFile(document);
        } catch (RBACException e) {
            try {
                deleteRole(role);
            } catch (Exception ex) {
                LOG.error("Error occured while trying to rollback the changes", e);
            }
            throw e;
        }
    }

    @Override
    public void deleteRole(String role) throws RoleNotFoundException, RBACException, RemoteException {
        OMDocument document = deleteElement(ROLE, role);
        updateConfigFile(document);
    }

    @Override
    public void assignUser(String user, String role) throws UserNotFoundException, RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void deassignUser(String user, String role) throws UserNotFoundException, RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void grantPermission(String role, String operation, String object) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void revokePermission(String role, String operation, String object) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addInheritance(String ascendant, String descendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void deleteInheritance(String ascendant, String descendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addAscendant(String ascendant, Property[] properties, String descendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addDescendant(String descendant, Property[] properties, String ascendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void setUserProperties(String user, Property[] properties) throws UserNotFoundException, RBACException, RemoteException {
        boolean passwordExists = false;
        SimpleDatabase sd = _securityProvider.getDatabase();
        String password = sd.getUser(IdentifierUtils.normalize(user, _realm, false, '\\')).getPassword();
        OMDocument document = deleteElement(USER, user);
        Property[] property = new Property[properties.length + 1];
        for (int i = 0; i < properties.length; i++) {
            property[i] = properties[i];
            if (property[i].getName().equals(PASSWORD)) {
                passwordExists = true;
            }
        }
        if (!passwordExists) {
            property[properties.length] = new Property(PASSWORD, password);
        }
        addElement(USER, user, property, document);
        try {
            updateConfigFile(document);
        } catch (RBACException e) {
            try {
                deleteRole(user);
            } catch (Exception ex) {
                LOG.error("Error occured while trying to rollback the changes", e);
            }
            throw e;
        }
    }

    @Override
    public void setRoleProperties(String role, Property[] properties) throws RoleNotFoundException, RBACException, RemoteException {
        OMDocument document = deleteElement(ROLE, role);
        addElement(ROLE, role, properties, document);
        try {
            updateConfigFile(document);
        } catch (RBACException e) {
            try {
                deleteRole(role);
            } catch (Exception ex) {
                LOG.error("Error occured while trying to rollback the changes", e);
            }
            throw e;
        }
    }

    private void updateConfigFile(OMDocument document) throws RBACException {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(_securityProvider.getConfigFile());
            document.serialize(fos);
        } catch (Exception e) {
            LOG.error("Error occured while writing to configuration file:", e);
            throw new RBACException(e.getMessage(), e);
        } finally {
            try {
                fos.flush();
                fos.close();
            } catch (IOException e) {
                LOG.error("Error occured while closing the outputstream:", e);
                throw new RBACException(e.getMessage(), e);
            }
        }
        try {
            _securityProvider.init();
        } catch (AuthenticationException e) {
            LOG.error("Error occured reloading security configuration: ", e);
            throw new RBACException(e.getMessage(), e);
        }
    }

    private OMDocument getDocumentElement() throws RBACException {
        XMLStreamReader parser = null;
        try {
            parser = XMLInputFactory.newInstance().createXMLStreamReader(_securityProvider.getConfigStream());
        } catch (Exception e) {
            LOG.error("Error occured while creating XMLStreamReader instance", e);
            throw new RBACException(e.getMessage());
        } catch (FactoryConfigurationError e) {
            LOG.error("Error occured while creating XMLStreamReader instance", e);
            throw new RBACException(e.getMessage());
        }
        StAXOMBuilder builder = new StAXOMBuilder(parser);
        return builder.getDocument();
    }

    private OMDocument deleteElement(String elementName, String elementValue) throws RBACException {
        OMDocument document = getDocumentElement();
        OMElement root = document.getOMDocumentElement();
        Iterator<OMElement> itr = root.getChildrenWithLocalName("realm");
        OMFactory factory = OMAbstractFactory.getOMFactory();
        while (itr.hasNext()) {
            OMElement realm = itr.next();
            if (realm.getAttribute(new QName("identifier")).getAttributeValue().equals(_realm)) {
                Iterator<OMElement> itrUser = realm.getChildrenWithLocalName(elementName);
                while (itrUser.hasNext()) {
                    OMElement roleElement = itrUser.next();
                    if (roleElement.getAttribute(new QName("identifier")).getAttributeValue().equals(elementValue)) {
                        roleElement.detach();
                    }
                }
                return document;
            }
        }
        return null;
    }

    private void addElement(String elementName, String elementValue, Property[] elementProperties, OMDocument document) throws RBACException {
        OMElement root = document.getOMDocumentElement();
        Iterator<OMElement> itr = root.getChildrenWithLocalName("realm");
        OMFactory factory = OMAbstractFactory.getOMFactory();
        while (itr.hasNext()) {
            OMElement realm = itr.next();
            if (realm.getAttribute(new QName("identifier")).getAttributeValue().equals(_realm)) {
                OMElement roleElement = factory.createOMElement(elementName, realm.getNamespace());
                OMAttribute identifier = factory.createOMAttribute("identifier", realm.getNamespace(), elementValue);
                roleElement.addAttribute(identifier);
                for (Property property : elementProperties) {
                    if (property != null) {
                        OMElement propertyElement = factory.createOMElement(property.getName(), realm.getNamespace());
                        propertyElement.setText(property.getValue().toString());
                        roleElement.addChild(propertyElement);
                    }
                }
                realm.addChild(roleElement);
                return;
            }
        }
    }

}
