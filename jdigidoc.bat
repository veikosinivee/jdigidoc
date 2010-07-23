REM jdigidoc utility
set JAVA_HOME=c:\Program Files (x86)\Java\jdk1.6.0_22
rem set JDIGIDOC_HOME=C:\jdigidoc
set JDIGIDOC_HOME=z:\workspace\jdigidoc\trunk
set CP=%JDIGIDOC_HOME%\lib\iaikPkcs11Wrapper.jar;%JDIGIDOC_HOME%\lib\jakarta-log4j-1.2.6.jar;%JDIGIDOC_HOME%\lib\jce-1_2_2.zip;%JDIGIDOC_HOME%\lib\xmlsec.jar;%JDIGIDOC_HOME%\lib\xalan.jar;%JDIGIDOC_HOME%\lib\xercesImpl.jar;%JDIGIDOC_HOME%\lib\xml-apis.jar;%JDIGIDOC_HOME%\lib\xmlParserAPIs.jar;%JDIGIDOC_HOME%\lib\bcpg-jdk15on-147.jar;%JDIGIDOC_HOME%\lib\bcprov-jdk15on-147.jar;%JDIGIDOC_HOME%\lib\bctsp-jdk15on-147.jar;%JDIGIDOC_HOME%\lib\bcmail-jdk16-144.jar;%JDIGIDOC_HOME%\lib\commons-codec-1.6.jar;%JDIGIDOC_HOME%\lib\commons-compress-1.3.jar;%JDIGIDOC_HOME%\tmp\jdigidoc.jar;%JDIGIDOC_HOME%\tmp\jdcerts.jar;.
"%JAVA_HOME%\bin\java" -Xmx512m -classpath %CP% ee.sk.test.jdigidoc -config %JDIGIDOC_HOME%\jdigidoc\src\main\resources\jdigidoc.cfg %*

