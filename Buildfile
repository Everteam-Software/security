require "buildr/xmlbeans"
require "buildr/cobertura"

# Keep this structure to allow the build system to update version numbers.
VERSION_NUMBER = "6.0.0.34-SNAPSHOT"

require "dependencies.rb"
require "repositories.rb"

desc "Securities"
define "securities" do
  project.version = VERSION_NUMBER
  project.group = "org.intalio.security"
  
  compile.options.target = "1.5"

  desc "Security Framework"
  define "security" do
    compile.with CAS_CLIENT, DOM4J, CASTOR, LOG4J, SLF4J, SPRING[:core], XERCES

    test.exclude "*BaseSuite"
    test.exclude "*FuncTestSuite"
    test.exclude "*LDAPAuthenticationTest*"
    test.exclude "*LDAPRBACProviderTest*"
    test.with JAXEN, XMLUNIT, INSTINCT
    
    package :jar
  end
  
  desc "Security Web-Service Common Library"
  define "security-ws-common" do
    compile.with project("security"), AXIOM, AXIS2, SLF4J, SPRING[:core], STAX_API 
    package :jar
  end
  
  desc "Security Web-Service Client"
  define "security-ws-client" do
    compile.with projects("security", "security-ws-common"),AXIOM, AXIS2, SLF4J, STAX_API, SPRING[:core]
    test.with APACHE_COMMONS[:httpclient], APACHE_COMMONS[:codec], CASTOR, LOG4J, SUNMAIL, XERCES, WS_COMMONS_SCHEMA, WSDL4J, WOODSTOX, CAS_CLIENT, INSTINCT

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
      jar.with :meta_inf => project("security-ws-service").path_to("src/main/axis2/*.wsdl")
    end
  end

  desc "Security Web-Service"
  define "security-ws-service" do
    compile.with projects("security", "security-ws-common"), AXIOM, AXIS2, SLF4J, SPRING[:core], STAX_API  
    package(:aar).with :libs => [ projects("security", "security-ws-common"), CASTOR, SLF4J, SPRING[:core], CAS_CLIENT ]
  end
  
  desc "Common spring and web related classes"
  define "web-nutsNbolts" do
    libs = AXIS2, APACHE_COMMONS[:lang], INTALIO_STATS, JSON_NAGGIT, JSP_API, LOG4J, SERVLET_API, SLF4J, SPRING[:core], SPRING[:webmvc]
    test_libs = libs + [JUNIT, INSTINCT, SPRING_MOCK, AXIOM, project("security-ws-client"), STAX_API, WSDL4J, WS_COMMONS_SCHEMA]
    compile.with projects("security"), test_libs
    package :jar
  end
end
