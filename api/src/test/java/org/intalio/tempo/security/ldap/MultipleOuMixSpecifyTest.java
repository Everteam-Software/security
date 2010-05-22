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
public class MultipleOuMixSpecifyTest {
    private static final String REALM = "intalio";
    private LDAPSecurityProvider ldap;
    private AuthenticationRuntime provider;
    private Property[] credentials;
    private RBACProvider rbac;

    @Before
    public void loginToLdap() throws Exception {
        String pathToLdap = this.getClass().getResource("/ldap_test_mix_multiple_ou.properties").getFile();
        
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
        Assert.assertTrue(loginAndCollectRoles("admin2@intalio.org", 1));
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
    
    @Test
    public void testUserProperties() throws Exception {
        Property[] p = rbac.getQuery().userProperties("admin3@intalio.org");
        for(int i=0;i< p.length;i++){
            System.out.print(p[i].getName() + ":");
            System.out.println(p[i].getValue());
        }
        p = rbac.getQuery().userProperties("admin2@intalio.org");
        for(int i=0;i< p.length;i++){
            System.out.print(p[i].getName() + ":");
            System.out.println(p[i].getValue());
        }
        p = rbac.getQuery().userProperties("admin5@intalio.org");
        for(int i=0;i< p.length;i++){
            System.out.print(p[i].getName() + ":");
            System.out.println(p[i].getValue());
        }
    }
    
    @Test
    public void testRoleProperties() throws Exception{
        Property[] p = rbac.getQuery().roleProperties("ProcessManager");
        for(int i=0;i< p.length;i++){
            System.out.print(p[i].getName() + ":");
            System.out.println(p[i].getValue());
        }
        p = rbac.getQuery().roleProperties("ProcessManager2");
        for(int i=0;i< p.length;i++){
            System.out.print(p[i].getName() + ":");
            System.out.println(p[i].getValue());
        }
    }

}
