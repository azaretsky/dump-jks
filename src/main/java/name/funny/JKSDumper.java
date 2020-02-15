package name.funny;

import name.funny.ber.BerValue;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

class JKSDumper implements AutoCloseable {
    private final byte[] passwordBytes;

    public JKSDumper(char[] password) {
        passwordBytes = new byte[password.length * 2];
        for (int i = 0; i < password.length; i++) {
            passwordBytes[2 * i] = (byte) (password[i] >> 8);
            passwordBytes[2 * i + 1] = (byte) password[i];
        }
        Arrays.fill(password, (char) 0);
    }

    // see sun/security/provider/JavaKeyStore.java, in particular the "engineLoad" method
    public void dumpJKS(InputStream inputStream) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(passwordBytes);
        md.update("Mighty Aphrodite".getBytes(StandardCharsets.UTF_8));
        try (DataInputStream dis = new DataInputStream(new DigestInputStream(new BufferedInputStream(inputStream), md))) {
            int magic = dis.readInt();
            if (magic != 0xfeedfeed) {
                throw new IOException(String.format("bad magic 0x%08x", magic));
            }
            int version = dis.readInt();
            if (version != 1 && version != 2) {
                throw new IOException(String.format("bad version %d", version));
            }
            int count = dis.readInt();
            for (int i = 0; i < count; i++) {
                int tag = dis.readInt();
                String alias = dis.readUTF();
                Date date = new Date(dis.readLong() * 1000);
                switch (tag) {
                case 1:
                    int keySize = dis.readInt();
                    byte[] keyBytes = dis.readNBytes(keySize);
                    System.out.println("key " + alias + ' ' + date);
                    decodeKey(keyBytes);
                    int nCerts = dis.readInt();
                    for (int j = 0; j < nCerts; j++) {
                        readCertificate(dis, version, "certificate " + j);
                    }
                    break;
                case 2:
                    readCertificate(dis, version, "certificate " + alias);
                    break;
                default:
                    throw new IOException(String.format("bad %d entry tag %d", i, tag));
                }
            }
            byte[] realDigest = md.digest();
            byte[] storedDigest = dis.readNBytes(realDigest.length);
            if (MessageDigest.isEqual(realDigest, storedDigest)) {
                System.out.println("correct store digest");
            } else {
                System.out.println("bad store digest");
            }
        }
    }

    private void decodeKey(byte[] keyBytes) throws IOException, NoSuchAlgorithmException {
        BerValue berValue;
        try {
            berValue = BerValue.fromBytes(keyBytes);
        } catch (IllegalArgumentException e) {
            System.err.print("strange key bytes: ");
            e.printStackTrace(System.err);
            hexdump(keyBytes);
            return;
        }
        byte[] protectedKey = extractKeyProtectorData(berValue);
        if (protectedKey == null) {
            hexdump(keyBytes);
        } else {
            dumpKey(protectedKey);
        }
    }

    @SuppressWarnings("PointlessArithmeticExpression")
    private static final byte[] keyProtectorOid = {1 * 40 + 3, 6, 1, 4, 1, 42, 2, 17, 1, 1};

    private static byte[] extractKeyProtectorData(BerValue pkcs8) {
        if (!pkcs8.matchConstructed(BerValue.TagClass.Universal, 16)) {
            return null;
        }
        if (pkcs8.children.size() != 2) {
            return null;
        }
        BerValue algId = pkcs8.children.get(0);
        if (!algId.matchConstructed(BerValue.TagClass.Universal, 16)) {
            return null;
        }
        if (algId.children.size() < 1 || algId.children.size() > 2) {
            return null;
        }
        BerValue algOid = algId.children.get(0);
        if (!algOid.matchPrimitive(BerValue.TagClass.Universal, 6)) {
            return null;
        }
        if (algOid.primitiveValue.limit() != keyProtectorOid.length) {
            return null;
        }
        for (int i = 0; i < algOid.primitiveValue.limit(); i++) {
            if (algOid.primitiveValue.get(i) != keyProtectorOid[i]) {
                return null;
            }
        }
        if (algId.children.size() == 2) {
            BerValue algParams = algId.children.get(1);
            if (!algParams.matchPrimitive(BerValue.TagClass.Universal, 5)) {
                return null;
            }
            if (algParams.primitiveValue.limit() > 0) {
                return null;
            }
        }
        BerValue encryptedKey = pkcs8.children.get(1);
        if (!encryptedKey.matchPrimitive(BerValue.TagClass.Universal, 4)) {
            return null;
        }
        byte[] keyBytes = new byte[encryptedKey.primitiveValue.limit()];
        encryptedKey.primitiveValue.rewind();
        encryptedKey.primitiveValue.get(keyBytes);
        return keyBytes;
    }

    private static void readCertificate(DataInputStream dis, int version, String description) throws IOException {
        String certType;
        if (version == 1) {
            certType = "X509";
        } else {
            certType = dis.readUTF();
        }
        int certSize = dis.readInt();
        byte[] certBytes = dis.readNBytes(certSize);
        System.out.println(description + ' ' + certType);
        hexdump(certBytes);
    }

    // copied almost verbatim from sun/security/provider/KeyProtector.java, the "recover" method
    private void dumpKey(byte[] keyBytes) throws IOException, NoSuchAlgorithmException {
        final int SALT_LEN = 20;
        final int DIGEST_LEN = 20;
        byte[] salt = new byte[SALT_LEN];
        System.arraycopy(keyBytes, 0, salt, 0, SALT_LEN);

        // Determine the number of digest rounds
        int encrKeyLen = keyBytes.length - SALT_LEN - DIGEST_LEN;
        int numRounds = encrKeyLen / DIGEST_LEN;
        if ((encrKeyLen % DIGEST_LEN) != 0) numRounds++;

        // Get the encrypted key portion and store it in "encrKey"
        byte[] encrKey = new byte[encrKeyLen];
        System.arraycopy(keyBytes, SALT_LEN, encrKey, 0, encrKeyLen);

        // Set up the byte array which will be XORed with "encrKey"
        byte[] xorKey = new byte[encrKey.length];

        int xorOffset;
        byte[] digest;
        int i;
        MessageDigest md = MessageDigest.getInstance("SHA");
        // Compute the digests, and store them in "xorKey"
        for (i = 0, xorOffset = 0, digest = salt;
             i < numRounds;
             i++, xorOffset += DIGEST_LEN) {
            md.update(passwordBytes);
            md.update(digest);
            digest = md.digest();
            md.reset();
            // Copy the digest into "xorKey"
            if (i < numRounds - 1) {
                System.arraycopy(digest, 0, xorKey, xorOffset,
                        digest.length);
            } else {
                System.arraycopy(digest, 0, xorKey, xorOffset,
                        xorKey.length - xorOffset);
            }
        }
        Arrays.fill(salt, (byte) 0);

        // XOR "encrKey" with "xorKey", and store the result in "plainKey"
        byte[] plainKey = new byte[encrKey.length];
        for (i = 0; i < plainKey.length; i++) {
            plainKey[i] = (byte) (encrKey[i] ^ xorKey[i]);
        }
        Arrays.fill(encrKey, (byte) 0);
        Arrays.fill(xorKey, (byte) 0);

        /*
         * Check the integrity of the recovered key by concatenating it with
         * the password, digesting the concatenation, and comparing the
         * result of the digest operation with the digest provided at the end
         * of <code>protectedKey</code>. If the two digest values are
         * different, throw an exception.
         */
        md.update(passwordBytes);
        md.update(plainKey);
        digest = md.digest();
        md.reset();
        for (i = 0; i < digest.length; i++) {
            if (digest[i] != keyBytes[SALT_LEN + encrKeyLen + i]) {
                throw new IOException("Cannot recover key");
            }
        }
        Arrays.fill(digest, (byte) 0);

        hexdump(plainKey);
        Arrays.fill(plainKey, (byte) 0);
    }

    private static void hexdump(byte[] bytes) {
        for (byte b : bytes) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }

    @Override
    public void close() {
        Arrays.fill(passwordBytes, (byte) 0);
    }
}
