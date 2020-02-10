package name.funny;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        char[] password = System.console().readPassword("Password: ");
        try (JKSDumper dumper = new JKSDumper(password);
             InputStream inputStream = new FileInputStream(args[1])) {
            dumper.dumpJKS(inputStream);
        }
    }
}
