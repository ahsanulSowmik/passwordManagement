import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;

class User {
    private static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHAR_UPPER = CHAR_LOWER.toUpperCase();
    private static final String NUMBER = "0123456789";
    private static final String SPECIAL_CHAR = "!@#$%&*()-_+=<>?";
    private static final String ALL_CHAR = CHAR_LOWER + CHAR_UPPER + NUMBER + SPECIAL_CHAR;

    private String userName;
    private String password;
    private String email;

    private String roleName;

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    private String encryptedPassword;


    // Constructor
    public User(String userName, String password, String email,String roleName) {
        this.userName = userName;
        this.password = password;
        this.email = email;
        this.roleName = roleName;
    }

    public User() {

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



    String websiteFilePath = "E:\\projects\\password_management_\\src\\files\\website.csv";
    static String gameFilePath = "E:\\projects\\password_management_\\src\\files\\game.csv";

    static String applicationFilePath = "E:\\projects\\password_management_\\src\\files\\application.csv";
    private static Scanner scanner = new Scanner(System.in);



    public void addWebsitePassword(String loggedInUserName) {
        System.out.println("*******************Adding Website Password*******************");
        System.out.print("Enter website name: ");
        String websiteName = scanner.next();
        System.out.print("Enter website URL: ");
        String url = scanner.next();

        System.out.print("If you want to use Auto generate password press 1: ");
        int autoGenerate = scanner.nextInt();
        String password;
        if(autoGenerate==1){

            password = generateRandomPassword();
            System.out.println("Auto Generated Password: " + password);
        }
        else{
            System.out.print("Enter password: ");
            password = scanner.next();
        }



        encryptedPassword = encryptPasswordForSave(password);

        writeWebsitePasswordsToCSV(websiteName, url, encryptedPassword, loggedInUserName);


        System.out.println("Website password added successfully.");
    }

    private void writeWebsitePasswordsToCSV(String websiteName, String url, String password, String loggedInUserName) {
        try (FileWriter writer = new FileWriter(websiteFilePath, true)) {
            writer.append(websiteName)
                    .append(",")
                    .append(url)
                    .append(",")
                    .append(password)
                    .append(",")
                    .append(loggedInUserName)
                    .append("\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Method to decrypt the password using DES
    public void showWebsitesForUser(String loggedInUserName) {
        System.out.println("Websites for user: " + loggedInUserName);
        Website website = null;


        List<Website> websites = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(websiteFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 4 && parts[3].equals(loggedInUserName)) {
                    String websiteName = parts[0];
                    String url = parts[1];
                    String encryptedPassword = parts[2];

                    // Decrypt the password before displaying
                    String decryptedPassword = decryptPassword(encryptedPassword);

                    // Create a Website object and add it to the list
                    website = new Website(parts[3], decryptedPassword, websiteName, url);
                    websites.add(website);

                }
            }

            website.showWebsitesList(websites);

            System.out.println("Press 1 to Edit : ");
            System.out.println("Press 2 to go back: ");
            int choice = scanner.nextInt();
            if (choice == 2) {
                Main main = new Main();
                main.userDashboard();
            } else if (choice == 1) {
                editWebsitePassword(loggedInUserName);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void editWebsitePassword(String loggedInUserName) {
        System.out.println("*******************Editing Website Password*******************");
        System.out.print("Enter website name to edit password: ");
        String websiteNameToEdit = scanner.next();

        // Read the existing data from the CSV file
        String updatedCsvContent = readwebsiteFilePathAndUpdate(websiteNameToEdit, loggedInUserName);

        // Write the updated data back to the CSV file
        writeUpdatedwebsiteFilePath(updatedCsvContent);
    }

    private String readwebsiteFilePathAndUpdate(String websiteNameToEdit, String loggedInUserName) {
        StringBuilder updatedCsvContent = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(websiteFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 4 && parts[3].equals(loggedInUserName) && parts[0].equals(websiteNameToEdit)) {
                    // Match found, update the password or other fields as needed
                    System.out.print("Enter new password: ");
                    String newPassword = scanner.next();
                    // Update the password in the line
                    parts[2] = encryptPasswordForSave(newPassword);
                }
                // Append the line to the updated content
                updatedCsvContent.append(String.join(",", parts)).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return updatedCsvContent.toString();
    }

    private void writeUpdatedwebsiteFilePath(String updatedCsvContent) {
        try (FileWriter writer = new FileWriter(websiteFilePath)) {
            writer.write(updatedCsvContent);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    void addGamePassword(String loggedInUserName) {
        System.out.println("*******************Adding Game Password*******************");
        System.out.print("Enter game name: ");
        String gameName = scanner.next();
        System.out.print("Enter developer name: ");
        String developerName = scanner.next();
        System.out.print("If you want to use Auto generate password press 1: ");
        int autoGenerate = scanner.nextInt();
        String password;
        if(autoGenerate==1){

            password = generateRandomPassword();
            System.out.println("Auto Generated Password: " + password);
        }
        else{
            System.out.print("Enter password: ");
            password = scanner.next();
        }

        String encryptedPassword = encryptPasswordForSave(password);

        Game game = new Game(loggedInUserName, encryptedPassword,  gameName, developerName);

        writeGamePasswordsToCSV(game);

        System.out.println("Game password added successfully.");
    }


    private static void writeGamePasswordsToCSV(Game game) {
        try (FileWriter writer = new FileWriter(gameFilePath, true)) {
            writer.append(game.getGameName())
                    .append(",")
                    .append(game.getDeveloperName())
                    .append(",")
                    .append(game.getPassword())
                    .append(",")
                    .append(game.getUserName())
                    .append("\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void showGameForUser(String loggedInUserName) {
        System.out.println("Games for user: " + loggedInUserName);
        List<Game> games = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(gameFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 4 && parts[3].equals(loggedInUserName)) {
                    String gameName = parts[0];
                    String gameDeveloperName = parts[1];
                    String encryptedPassword = parts[2];

                    // Decrypt the password before displaying
                    String decryptedPassword = decryptPassword(encryptedPassword);

                    // Create a Game object and add it to the list
                    Game game = new Game(loggedInUserName, decryptedPassword, gameName, gameDeveloperName);
                    games.add(game);
                }
            }

            // Display the list of games
            for (int i = 0; i < games.size(); i++) {
                Game game = games.get(i);
                System.out.println("Game " + (i + 1) + ": " +
                        "Name: " + game.getGameName() +
                        ", Developer: " + game.getDeveloperName() +
                        ", Password: " + game.getPassword());
            }

            // Add your menu options here (Edit, Go back, etc.)
            System.out.println("Press 1 to Edit");
            System.out.println("Press 2 to go back");
            int choice = scanner.nextInt();
            if (choice == 1) {
                editGamePassword(loggedInUserName);
            } else if (choice == 2) {
                Main main = new Main();
                main.userDashboard();
            } else {
                System.out.println("Invalid choice");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void editGamePassword(String loggedInUserName) {
        System.out.println("*******************Editing Game Password*******************");
        System.out.print("Enter Game name to edit password: ");
        String gameNameToEdit = scanner.next();

        // Read the existing data from the CSV file
        String updatedCsvContent = readGameFilePathAndUpdate(gameNameToEdit, loggedInUserName);

        // Write the updated data back to the CSV file
        writeUpdatedGameFilePath(updatedCsvContent);
    }

    private String readGameFilePathAndUpdate(String gameNameToEdit, String loggedInUserName) {
        StringBuilder updatedCsvContent = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(gameFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 4 && parts[3].equals(loggedInUserName) && parts[0].equals(gameNameToEdit)) {
                    // Match found, update the password or other fields as needed
                    System.out.print("Enter new password: ");
                    String newPassword = scanner.next();
                    // Update the password in the line
                    parts[2] = encryptPasswordForSave(newPassword);
                }
                // Append the line to the updated content
                updatedCsvContent.append(String.join(",", parts)).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return updatedCsvContent.toString();
    }

    private void writeUpdatedGameFilePath(String updatedCsvContent) {
        try (FileWriter writer = new FileWriter(gameFilePath)) {
            writer.write(updatedCsvContent);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    void addApplicationPassword(String loggedInUserName) {
        System.out.println("*******************Adding Application Password*******************");
        System.out.print("Enter application name: ");
        String appName = scanner.next();
        System.out.print("If you want to use Auto generate password press 1: ");
        int autoGenerate = scanner.nextInt();
        String password;
        if(autoGenerate==1){
            password = generateRandomPassword();
            System.out.println("Auto Generated Password: " + password);
        }
        else{
            System.out.print("Enter password: ");
            password = scanner.next();
        }

        String encryptedPassword = encryptPasswordForSave(password);

        Application application = new Application(loggedInUserName, encryptedPassword,appName);

        writeApplicationPasswordsToCSV(application);
        System.out.println("Application password added successfully.");
    }

    private static void writeApplicationPasswordsToCSV(Application application) {
        try (FileWriter writer = new FileWriter(applicationFilePath, true)) {
            writer.append(application.getApplicationName())
                    .append(",")
                    .append(application.getPassword())
                    .append(",")
                    .append(application.getUserName())
                    .append("\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void showApplicationForUser(String loggedInUserName) {
        System.out.println("Application for user: " + loggedInUserName);
        List<Application> applications = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(applicationFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 3 && parts[2].equals(loggedInUserName)) {
                    String appName = parts[0];
                    String encryptedPassword = parts[1];
                    String decryptedPassword = decryptPassword(encryptedPassword);

                    // Create a Game object and add it to the list
                    Application application = new Application(loggedInUserName, decryptedPassword,appName);
                    applications.add(application);
                }
            }

            // Display the list of games
            for (int i = 0; i < applications.size(); i++) {
                Application application = applications.get(i);
                System.out.println("Game " + (i + 1) + ": " +
                        "Name: " + application.getApplicationName() +
                        ", Password: " + application.getPassword());
            }

            System.out.println("Press 1 to Edit");
            System.out.println("Press 2 to go back");
            int choice = scanner.nextInt();
            if (choice == 1) {
                editAppPassword(loggedInUserName);
            } else if (choice == 2) {
                Main main = new Main();
                main.userDashboard();
            } else {
                System.out.println("Invalid choice");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void editAppPassword(String loggedInUserName) {
        System.out.println("**********Editing Application Password***********");
        System.out.print("Enter Application name to edit password: ");
        String applicationNameToEdit = scanner.next();

        // Read the existing data from the CSV file
        String updatedCsvContent = readAppFilePathAndUpdate(applicationNameToEdit, loggedInUserName);

        // Write the updated data back to the CSV file
        writeUpdatedAppFilePath(updatedCsvContent);
    }

    private String readAppFilePathAndUpdate(String applicationNameToEdit, String loggedInUserName) {
        StringBuilder updatedCsvContent = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(applicationFilePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 3 && parts[2].equals(loggedInUserName) && parts[0].equals(applicationNameToEdit)) {
                    // Match found, update the password or other fields as needed
                    System.out.print("Enter new password: ");
                    String newPassword = scanner.next();
                    // Update the password in the line
                    parts[1] = encryptPasswordForSave(newPassword);
                }
                // Append the line to the updated content
                updatedCsvContent.append(String.join(",", parts)).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return updatedCsvContent.toString();
    }

    private void writeUpdatedAppFilePath(String updatedCsvContent) {
        try (FileWriter writer = new FileWriter(applicationFilePath)) {
            writer.write(updatedCsvContent);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String encryptPasswordForSave(String password) {
        try {
            // Use a secure encryption key or algorithm
            String encryptionKey = "YourSecureEncryptionKey";
            KeySpec keySpec = new DESKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey myDesKey = keyFactory.generateSecret(keySpec);

            Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);

            byte[] encryptedPasswordBytes = desCipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

            // Encode the encrypted bytes to Base64
            return Base64.getEncoder().encodeToString(encryptedPasswordBytes);
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

    public static String generateRandomPassword() {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        for (int i = 0; i < 5; i++) {
            int randomIndex = random.nextInt(ALL_CHAR.length());
            password.append(ALL_CHAR.charAt(randomIndex));
        }

        return password.toString();
    }


}
