package com.github.kohanyirobert.keytool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

public class Main {

  public static void main(String[] args) throws Exception {
    System.exit(new Main(args).run());
  }

  private final List<String> args;

  private String command;

  private boolean help;
  private boolean rfc;
  private String keystore;
  private String storetype;
  private String storepass;
  private String alias;
  private String keypass;
  private String file;

  private Main(String[] args) {
    this(Arrays.asList(args));
  }

  private Main(List<String> args) {
    this.args = args;
  }

  private int run() throws Exception {
    return ok() ? handle() : giveup();
  }

  private boolean ok() {
    for (String arg : args)
      if (Arrays.asList(
          "-certreq",
          "-changealias",
          "-delete",
          "-exportcert",
          "-exportpubkey",
          "-exportprivkey",
          "-genkeypair",
          "-genseckey",
          "-gencert",
          "-importcert",
          "-importkeystore",
          "-keypasswd",
          "-list",
          "-printcert",
          "-printcertreq",
          "-printcrl",
          "-storepasswd").contains(arg.toLowerCase()))
        command = arg;

    return exportpubkey() || exportprivkey();
  }

  private int handle() throws Exception {
    int exit = parse();

    if (exit == 0) {
      if (help)
        System.err.printf("%s%n%s%n", "", help());

      else {
        keystore = keystore == null
            ? System.getProperty("user.home", ".") + System.getProperty("file.separator", "/") + ".keystore"
            : keystore;

        storetype = storetype == null ? Security.getProperty("keystore.type") : storetype;

        storepass = storepass == null ? null : storepass;

        alias = alias == null ? "mykey" : alias;

        keypass = keypass == null ? storepass : keypass;

        file = file == null ? null : file;

        // keystore
        if (new File(keystore).exists()) {
          ;
        } else {
          System.err.printf("keytool error: %s: Keystore file does not exist: %s%n", Exception.class.getName(),
              keystore);
          return 1;
        }

        // storetype
        KeyStore keyStore;
        try {
          keyStore = KeyStore.getInstance(storetype);
        } catch (KeyStoreException ex) {
          System.err.printf("keytool error: %s%n", ex);
          return 1;
        }

        // storepass
        if (storepass == null) {
          if (exportpubkey()) {
            System.err.printf("Enter keystore password: ");
            storepass = System.console() == null
                ? new Scanner(System.in).nextLine()
                : new String(System.console().readPassword());

          } else {
            for (int i = 0; i < 3; i++) {
              System.err.printf("Enter keystore password: ");
              storepass = System.console() == null
                  ? new Scanner(System.in).nextLine()
                  : new String(System.console().readPassword());

              if (storepass == null || storepass.length() < 6) {
                System.err.printf("Keystore password is too short - must be at least 6 characters%n");
                continue;
              }

              break;
            }

            if (storepass == null || storepass.length() < 6) {
              System.err.printf("Too many failures - try later%n");
              return 1;
            }
          }
        }

        try (InputStream in = new FileInputStream(keystore)) {
          keyStore.load(in, "".equals(storepass) ? null : storepass.toCharArray());
        } catch (IOException ex) {
          if (ex.getCause() instanceof UnrecoverableKeyException) {
            System.err.printf("keytool error: %s%n", ex);
            return 1;
          }
          throw ex;
        }

        if ("".equals(storepass))
          System.err.printf("%n%s%n%n", warning());

        // alias
        if (keyStore.containsAlias(alias))
          ;
        else {
          System.err.printf("keytool error: %s: Alias <%s> does not exist%n", Exception.class.getName(), alias);
          return 1;
        }

        Key key;
        if (exportpubkey())
          key = keyStore.getCertificate(alias).getPublicKey();

        else {
          // keypass
          try {
            key = keyStore.getKey(alias, keypass == null ? storepass.toCharArray() : keypass.toCharArray());
          } catch (UnrecoverableKeyException outerEx) {
            for (int i = 0; i < 3; i++) {
              System.err.printf("Enter keystore password for <%s>: ", alias);
              keypass = System.console() == null
                  ? new Scanner(System.in).nextLine()
                  : new String(System.console().readPassword());

              if (keypass == null || keypass.length() < 6)
                continue;

              break;
            }

            if (keypass == null || keypass.length() < 6) {
              System.err.printf("keytool error: %s: Too many failures - try later%n", Exception.class.getName());
              return 1;
            }

            try {
              key = keyStore.getKey(alias, keypass.toCharArray());
            } catch (UnrecoverableKeyException innerEx) {
              System.err.printf("keytool error: %s: Cannot recover key%n", innerEx.getClass().getName());
              return 1;
            }
          }
        }

        byte[] binary = key.getEncoded();
        String base64 = DatatypeConverter.printBase64Binary(binary);

        try (PrintStream out = file == null ? System.out : new PrintStream(file)) {
          if (rfc) {
            out.printf("-----BEGIN %s KEY-----%n", exportpubkey() ? "PUBLIC" : "PRIVATE");
            for (int i = 0; i < base64.length(); i++) {
              if (i > 0 && i % 76 == 0 && i < base64.length() - 1)
                out.printf("%n");
              out.print(base64.charAt(i));
            }
            out.printf("%n-----END %s KEY-----%n", exportpubkey() ? "PUBLIC" : "PRIVATE");
          } else
            out.write(binary);
        }
      }
    }

    return exit;
  }

  private int parse() {
    Iterator<String> i = args.iterator();
    while (i.hasNext()) {
      String arg = i.next();

      try {
        if ("-exportpubkey".equalsIgnoreCase(arg))
          ;

        else if ("-exportprivkey".equalsIgnoreCase(arg))
          ;

        else if ("-help".equalsIgnoreCase(arg))
          help = true;

        else if ("-rfc".equalsIgnoreCase(arg))
          rfc = true;

        else if ("-keystore".equalsIgnoreCase(arg))
          keystore = i.next();

        else if ("-storetype".equalsIgnoreCase(arg))
          storetype = i.next();

        else if ("-storepass".equalsIgnoreCase(arg))
          storepass = i.next();

        else if ("-alias".equalsIgnoreCase(arg) && i.hasNext())
          alias = i.next();

        else if ("-keypass".equalsIgnoreCase(arg) && exportprivkey() && i.hasNext())
          keypass = i.next();

        else if ("-file".equalsIgnoreCase(arg) & i.hasNext())
          file = i.next();

        else {
          System.err.printf("Illegal option:  %s%n%s%n", arg, help());
          return 1;
        }

      } catch (NoSuchElementException ex) {
        System.err.printf("Command option %s needs an argument.%n%s%n", arg, help());
        return 1;
      }
    }

    return 0;
  }

  private int giveup() {
    return 255;
  }

  private String help() {
    try (Scanner scanner = new Scanner(Main.class.getResourceAsStream(command))) {
      return scanner.useDelimiter("^").next();
    }
  }

  private String warning() {
    try (Scanner scanner = new Scanner(Main.class.getResourceAsStream("warning.txt"))) {
      return scanner.useDelimiter("^").next();
    }
  }

  private boolean exportpubkey() {
    return "-exportpubkey".equalsIgnoreCase(command);
  }

  private boolean exportprivkey() {
    return "-exportprivkey".equalsIgnoreCase(command);
  }
}
