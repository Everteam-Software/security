package org.intalio.tempo.security.ldap;

import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationConstants;
import org.intalio.tempo.security.authentication.AuthenticationRuntime;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * This is a live test to test multiple OUs.
 * Related test files are:
 * - ldap_test.properties, for the LDAP mappings
 * - test_multiple_ou.ldap, for an example of a LDAP file to import
 *
 */
public class MultipleOuTest {
	String pathToLdap = this.getClass().getResource("/ldap_test.properties").getFile();
	private LDAPSecurityProvider ldap;
	private AuthenticationRuntime provider;
	private Property[] credentials;

	@Before
	public void loginToLdap() throws Exception {
		ldap = new LDAPSecurityProvider();
		ldap.setPropertiesFile(pathToLdap);
		provider = ldap.getAuthenticationProvider("intalio").getRuntime();
		
		String password = "changeit";
		Property pwd = new Property( AuthenticationConstants.PROPERTY_PASSWORD, password );
		credentials = new Property[] { pwd };
	}
	
	@Test
	public void testStandardOu() throws Exception {	
		Assert.assertTrue(provider.authenticate("admin", credentials));
	}
	
	@Test
	public void testSecondOu() throws Exception {	
		Assert.assertTrue(provider.authenticate("admin2", credentials));
	}
	
	@Test
	public void testInnerOu() throws Exception {	
		Assert.assertTrue(provider.authenticate("admin3", credentials));
	}
	
	
}
