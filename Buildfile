# Some test comment & some more & 1 more & 2 more & 3 more & 4 more & 5
require "buildr/xmlbeans"
require "buildr/cobertura"
require "install.rb"

# Keep this structure to allow the build system to update version numbers.
VERSION_NUMBER = "7.0.0-SNAPSHOT"

desc "Security"
define "security" do
  project.version = VERSION_NUMBER
  project.group = "org.intalio.security"
  
  compile.options.source = "1.5"  
  compile.options.target = "1.5"

  desc "Security Framework"
  define "api" do
    compile.with AXIOM, CAS_CLIENT, DOM4J, CASTOR, LOG4J, SLF4J[:api], SLF4J[:log4j12], SLF4J[:jcl104overslf4j], SPRING[:core], XERCES[:impl], XERCES[:parserapi], OPENSSO_CLIENT_SDK, SERVLET_API,JASYPT

    test.exclude "*BaseSuite"
    test.exclude "*FuncTestSuite"
    test.exclude "*LDAPAuthenticationTest*"
    test.exclude "*MultipleOuTest*"
	test.exclude "*MultipleOuSpecifyTest*"
    test.exclude "*LDAPRBACProviderTest*"
	test.exclude "*MultipleOuMixSpecifyTest*"
    test.with JAXEN, XMLUNIT, INSTINCT
    
    package :jar
  end
  
  desc "Security Web-Service Common Library"
  define "ws-common" do
    compile.with project("api"),APACHE_COMMONS[:httpclient], AXIOM, AXIS2.values, SLF4J[:api], SLF4J[:log4j12], SLF4J[:jcl104overslf4j], SPRING[:core], STAX_API ,JASYPT
    package :jar
  end
  
  desc "Security Web-Service Client"
  define "ws-client" do
    compile.with projects("api", "ws-common"),JASYPT,AXIOM, AXIS2.values, SLF4J[:api], SLF4J[:log4j12], SLF4J[:jcl104overslf4j], STAX_API,APACHE_COMMONS[:httpclient], SPRING[:core], BPMS_COMMON
    test.with APACHE_COMMONS[:httpclient], APACHE_COMMONS[:codec], CASTOR, LOG4J, SUNMAIL, XERCES[:impl], XERCES[:parserapi], WS_COMMONS_SCHEMA, WSDL4J, WOODSTOX, CAS_CLIENT, INSTINCT, BPMS_COMMON

    # Remember to set JAVA_OPTIONS before starting Jetty
    # export JAVA_OPTIONS=-Dorg.intalio.tempo.configDirectory=/home/boisvert/svn/tempo/security-ws2/src/test/resources
    
    # require live Axis2 instance
    if ENV["LIVE"] == 'yes'
      LIVE_ENDPOINT = "http://localhost:8080/axis2/services/TokenService"
    end
    
    if defined? LIVE_ENDPOINT
      test.using :properties => 
        { "org.intalio.tempo.security.ws.endpoint" => LIVE_ENDPOINT,
          "org.intalio.tempo.configDirectory" => _("src/test/resources") }
    end

    package(:jar).tap do |jar|
      jar.with :meta_inf => project("ws-service").path_to("src/main/axis2/*.wsdl")
    end
  end

  desc "Security Web-Service"
  define "ws-service" do
    compile.with projects("api", "ws-common"), AXIOM, AXIS2.values, SLF4J[:api], SLF4J[:log4j12], SLF4J[:jcl104overslf4j], SPRING[:core], STAX_API  
    package(:aar).with :libs => [ projects("api", "ws-common"), CASTOR, SLF4J[:api], SLF4J[:log4j12], SLF4J[:jcl104overslf4j], SPRING[:core], CAS_CLIENT ]
  end
  
  desc "Common spring and web related classes"
  define "web-nutsNbolts" do
    libs = AXIS2.values, APACHE_COMMONS[:lang], INTALIO_STATS, JSON_NAGGIT, JSP_API, LOG4J, SERVLET_API, SLF4J[:api], SLF4J[:log4j12], SLF4J[:jcl104overslf4j], SPRING[:core], SPRING[:webmvc], APACHE_COMMONS[:httpclient]
    test_libs = libs + [JUNIT, INSTINCT, SPRING[:mock], AXIOM, project("ws-client"), STAX_API, WSDL4J, WS_COMMONS_SCHEMA]
    compile.with projects("api"), test_libs
    package :jar
  end
end
