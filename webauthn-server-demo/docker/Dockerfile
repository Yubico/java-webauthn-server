FROM tomcat:jre8

RUN rm -rf /usr/local/tomcat/webapps/*

COPY server.xml /usr/local/tomcat/conf/server.xml
COPY webauthn-server-demo.war /usr/local/tomcat/webapps/ROOT.war
