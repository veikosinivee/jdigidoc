#!/bin/bash

function check_error {
    if [ "$?" != "0" ]; then
        echo "+++++++++++++++++++++++++++++++++++++++++++++"
        echo "            BUILD FAILED !!!"
        echo "+++++++++++++++++++++++++++++++++++++++++++++"
        exit 1
    fi

}

function build_jdigidoc {
    #---- cleanup build dir
    rm -rf build
    mkdir build
    rm -rf jdigidoc/jdigidoc/target

    #---- build jdigidoc jar, remove test certificates
    cd jdigidoc/jdigidoc
    mvn install -DJDD_VERSION=$JDD_VERSION
    check_error
    zip -d target/jdigidoc-$JDD_VERSION.jar "certs/TEST*.crt" jdigidoc.cfg jdigidoc-win.cfg log4j.properties openxades.jks jdigidoc.sh jdigidoc.bat
    check_error
    cp target/jdigidoc-$JDD_VERSION.jar ../../build
    cp src/main/resources/jdigidoc.cfg ../../build
    cp *.txt ../../build
    cp src/main/resources/log4j.properties ../../build
    mv ../lib/jdcerts.jar ../../build

    #---- build test certificates jar
    mkdir -p certs
    cp -r src/main/resources/certs/TEST*.crt certs/
    check_error
    jar -cf ../../build/esteidtestcerts.jar certs/
    check_error

    cd ..

    #---- cleanup tmp directory
    echo currentVersion=$JDD_VERSION>version.properties
    rm -rf tmp/*

    #---- build javadoc and source pakcage
    ant javadoc
    check_error
    cp tmp/jdigidoc-$JDD_VERSION-javadoc.zip ../build
    ant source
    check_error
    cp tmp/jdigidoc-$JDD_VERSION-source.jar ../build
    check_error

    #---- builds jdigidoc utility package
    ant -f create_util_jar_build.xml -Dversion=$JDD_VERSION
    check_error
    cp jdigidocutil-$JDD_VERSION.jar ../build
    check_error

    cd ../build

    #---- create ditributable zip

    zip -m jdigidoc-$JDD_VERSION.zip log4j.properties jdigidoc.cfg *.txt jdigidoc-$JDD_VERSION.jar jdigidocutil-$JDD_VERSION.jar jdigidoc-$JDD_VERSION-javadoc.zip jdigidoc-$JDD_VERSION-source.jar
    cd ../jdigidoc
    zip -ur ../build/jdigidoc-$JDD_VERSION.zip lib -x *.svn* -x *windows* -x lib/jdcerts.jar
    zip -ur ../build/jdigidoc-$JDD_VERSION.zip doc -x *.svn*
}

build_jdigidoc