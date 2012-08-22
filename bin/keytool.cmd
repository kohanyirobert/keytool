@echo off
"%JAVA_HOME%\bin\java" -cp "%KEYTOOL_HOME%\target\classes" com.github.kohanyirobert.keytool.Main %*
if errorlevel 255 "%JAVA_HOME%\bin\keytool.exe" %*
