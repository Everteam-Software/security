package org.intalio.tempo.security.ldap;

import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationConstants;
import org.intalio.tempo.security.authentication.AuthenticationRuntime;
import org.intalio.tempo.security.rbac.provider.RBACProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * This is a live test to test multiple OUs. Related test files are:
 * - ldap_test.properties, for the LDAP mappings 
 * - test_multiple_ou.ldap, for an example of a LDAP file to import
 */
public class MultipleOuSpecifyTest {
    private static final String REALM = "intalio";
    private LDAPSecurityProvider ldap;
    private AuthenticationRuntime provider;
    private Property[] credentials;
    private RBACProvider rbac;

    @Before
    public void loginToLdap() throws Exception {
        String pathToLdap = this.getClass().getResource("/ldap_test_multiple_ou.properties").getFile();
        
        ldap = new LDAPSecurityProvider();
        ldap.setPropertiesFile(pathToLdap);
        provider = ldap.getAuthenticationProvider(REALM).getRuntime();
        rbac = ldap.getRBACProvider(REALM);

        String password = "changeit";
        Property pwd = new Property(AuthenticationConstants.PROPERTY_PASSWORD, password);
        credentials = new Property[] { pwd };
    }

    @Test
    public void testStandardOu() throws Exception {
        Assert.assertTrue(loginAndCollectRoles("admin@intalio.org", 2));
    }

    private boolean loginAndCollectRoles(String userId, int rolesInd) throws Exception {
        boolean authenticate = provider.authenticate(userId, credentials);
        if (!authenticate)
            return Boolean.FALSE;
        String[] roles = rbac.getQuery().assignedRoles(userId);
        Assert.assertEquals(rolesInd, roles.length);
        return Boolean.TRUE;
    }

    @Test
    public void testSecondOu() throws Exception {
        Assert.assertTrue(loginAndCollectRoles("admin2@intalio.org", 2));
    }

    @Test
    public void testInnerOu() throws Exception {
        Assert.assertTrue(loginAndCollectRoles("admin3@intalio.org", 1));
    }

    @Test
    public void testNoRole() throws Exception {
    	Assert.assertTrue(loginAndCollectRoles("admin4@intalio.org", 0));
    }
    
    @Test
    public void testFailedOu() throws Exception {
    	Assert.assertFalse(provider.authenticate("admin5", credentials));
    }

}
