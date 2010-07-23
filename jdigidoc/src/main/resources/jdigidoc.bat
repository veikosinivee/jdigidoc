REM jdigidoc utility
set JDIGIDOC_HOME=C:\jdigidoc
set CP=%JDIGIDOC_HOME%\iaikPkcs11Wrapper.jar;%JDIGIDOC_HOME%\jakarta-log4j-1.2.6.jar;%JDIGIDOC_HOME%\xmlsec.jar;%JDIGIDOC_HOME%\xalan.jar;%JDIGIDOC_HOME%\xercesImpl.jar;%JDIGIDOC_HOME%\xml-apis.jar;%JDIGIDOC_HOME%\xmlParserAPIs.jar;%JDIGIDOC_HOME%\bcprov-jdk16-144.jar;%JDIGIDOC_HOME%\bctsp-jdk16-144.jar;%JDIGIDOC_HOME%\bcmail-jdk16-144.jar;%JDIGIDOC_HOME%\commons-codec-1.6.jar;%JDIGIDOC_HOME%\commons-compress-1.3.jar;%JDIGIDOC_HOME%\JDigiDoc.jar;.
"%JAVA_HOME%\bin\java" -Xmx512m -classpath %CP% ee.sk.test.jdigidoc -config %JDIGIDOC_HOME%\jdigidoc.cfg %*

