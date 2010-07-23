#!/bin/bash

JAVA=java
#JAVA=/System/Library/Frameworks/JavaVM.framework/Versions/1.4.2/Home/bin/java

#dir=`dirname $0`
if [ -z "$JDIGIDOC_HOME" ]; then
	dir=`dirname $0`
else
	dir=$JDIGIDOC_HOME
fi

for i in $dir/tmp/*.jar $dir/lib/*.jar; do
	CLASSPATH="$CLASSPATH:$i"
done

echo "CP=" $CLASSPATH
# java -Xmx512m -classpath $CLASSPATH ee.sk.test.jdigidoc -config jar://jdigidoc.cfg "$@"
$JAVA -Xmx2048m -classpath $CLASSPATH ee.sk.test.jdigidoc -config $dir/jdigidoc.cfg "$@"
