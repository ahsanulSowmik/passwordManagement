import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

class User {
    private String userName;
    private String password;
    private String email;

    private String encryptedPassword;

    // Constructor
    public User(String userName, String password, String email) {
        this.userName = userName;
        this.password = password;
        this.email = email;
    }

    // Getter methods
    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void encryptPassword(String encryptionKey) {
        try {
            KeySpec keySpec = new DESKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey myDesKey = keyFactory.generateSecret(keySpec);

            Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);

            byte[] encryptedPasswordBytes = desCipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

            // Encode the encrypted bytes to Base64
            this.encryptedPassword = Base64.getEncoder().encodeToString(encryptedPasswordBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to decrypt the password using DES
    public String decryptPassword(String encryptionKey) {
        try {
            KeySpec keySpec = new DESKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey myDesKey = keyFactory.generateSecret(keySpec);

            Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            desCipher.init(Cipher.DECRYPT_MODE, myDesKey);

            // Validate Base64 string
            if (!isValidBase64(this.encryptedPassword)) {
                System.err.println("Invalid Base64 string");
                return null;
            }

            // Decode the Base64 string before decryption
            byte[] decodedBytes = Base64.getDecoder().decode(this.encryptedPassword);

            byte[] decryptedPasswordBytes = desCipher.doFinal(decodedBytes);
            return new String(decryptedPasswordBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to check if a string is a valid Base64 encoding
    private static boolean isValidBase64(String str) {
        try {
            Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
