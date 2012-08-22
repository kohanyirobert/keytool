@echo off
"%JAVA_HOME%\bin\java" -agentlib:jdwp=transport=dt_socket,server=y,address=8000,suspend=y -cp "%KEYTOOL_HOME%\target\classes" com.github.kohanyirobert.keytool.Main %*
if errorlevel 255 "%JAVA_HOME%\bin\keytool.exe" %*
