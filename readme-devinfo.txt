JDigiDoc developers info

You need the following dependent librarys to build jdigidoc:
- commons-codec-1.6.jar - http://commons.apache.org/proper/commons-codec/download_codec.cgi
- commons-compress-1.3.jar - http://commons.apache.org/proper/commons-compress/download_compress.cgi
- bcmail-jdk15on-151.jar - http://www.bouncycastle.org/latest_releases.html
- bcpkix-jdk15on-151.jar - http://www.bouncycastle.org/latest_releases.html
- bcprov-jdk15on-151.jar - http://www.bouncycastle.org/latest_releases.html
- jakarta-log4j-1.2.6.jar - https://archive.apache.org/dist/jakarta/log4j/binaries/
- iaikPkcs11Wrapper.jar - http://jce.iaik.tugraz.at/sic/Products/Core-Crypto-Toolkits/PKCS_11_Wrapper

Download them all to some directory and edit build.xml entry:
<property name="lib.dir" location="${env.HOME}/libs/jdigidoc" />
to point to that directory.

To build jdigidoc library use:
ant jar
This command also build jdcerts.jar that contains addition CA certificates for
testing environments only.

To build a zip file with dependent libs for distribution use
ant deplibs
