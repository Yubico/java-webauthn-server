Custom Lombok build that also copies javadoc from field definitions to builder
setters.

Build using the `lombok` submodule. Building Lombok requires JDK 10, therefore
it is not integrated directly into the Gradle build. It is built as such:

```
$ git submodule update --init
$ cd lombok
$ ant setupJavaOracle8TestEnvironment
$ rm ../lombok.config
$ ant test
$ ant dist
$ cp dist/lombok-1.18.5.jar ../lib/com/yubico/lombok/1.18.5-custom/lombok-1.18.5-custom.jar
$ cd ..
$ git checkout -- lombok.config
```
