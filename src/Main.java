import java.io.*;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;
import java.util.Scanner;

public class Main {
    private static final String CSV_FILE = "E:\\projects\\password_management_\\src\\files\\user.csv";

    public static String loggedInUserName;

    public static String roleName;


    public static void main(String[] args) {


        Scanner scanner = new Scanner(System.in);

        int choice;

        do {
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Enter your choice: ");
            choice = scanner.nextInt();

            switch (choice) {
                case 1:
                    registerUser();
                    break;
                case 2:
                    if (loginUser()) {
                        // If login is successful, enter the user dashboard
                        if(loggedInUserName.equals("admin")){
                            adminDashboard();
                        }
                        else{
                            userDashboard();
                        }

                    } else {
                        System.out.println("Login failed. Please try again.");
                    }
                    break;
                case 3:
                    System.out.println("Exiting the program. Goodbye!");
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }

        } while (choice != 3);


    }

    public static void userDashboard() {

        User user = new User();
        Scanner scanner = new Scanner(System.in);
        int choice;


        System.out.println("1. Add Website Password");
        System.out.println("2. All Website Password");
        System.out.println("3. Add Game Password");
        System.out.println("4. All Game Passwords");
        System.out.println("5. Add Application Password");
        System.out.println("6. All Application Passwords");
        System.out.println("7. Exit");
        System.out.print("Enter your choice: ");
        choice = scanner.nextInt();

        switch (choice) {
            case 1:
                user.addWebsitePassword(loggedInUserName);
                break;
            case 2:
                user.showWebsitesForUser(loggedInUserName);
                break;
            case 3:
                user.addGamePassword(loggedInUserName);
                break;
            case 4:
                user.showGameForUser(loggedInUserName);
                break;
            case 5:
                user.addApplicationPassword(loggedInUserName);
                break;
            case 6:
                user.showApplicationForUser(loggedInUserName);
                break;
            case 7:
                System.out.println("Exiting Password Manager. Goodbye!");
                break;
            default:
                System.out.println("Invalid choice. Please try again.");
        }


    }

    public static void adminDashboard() {

        User user = new User();
        Scanner scanner = new Scanner(System.in);
        int choice;

        System.out.println("1. All User");
        System.out.println("2. Add Website Password for user");
        System.out.println("3. All Website Password Individual User");
        System.out.println("4. Add Game Password for user");
        System.out.println("5. All Game Passwords Individual User");
        System.out.println("6. Add Application Password for user");
        System.out.println("7. All Application Passwords Individual User");
        System.out.println("8. Exit");
        System.out.print("Enter your choice: ");
        choice = scanner.nextInt();
        String userName;

        switch (choice) {
            case 1:
                showAllUser();
                break;
            case 2:
                System.out.print("Enter User Name: ");
                userName = scanner.next();
                user.addWebsitePassword(userName);
                break;
            case 3:
                System.out.print("Enter User Name: ");
                userName = scanner.next();
                user.showWebsitesForUser(userName);
                break;
            case 4:
                System.out.print("Enter User Name: ");
                userName = scanner.next();
                user.addGamePassword(userName);
                break;
            case 5:
                System.out.print("Enter User Name: ");
                userName = scanner.next();
                user.showGameForUser(userName);
                break;
            case 6:
                System.out.print("Enter User Name: ");
                userName = scanner.next();
                user.addApplicationPassword(userName);
                break;
            case 7:
                System.out.print("Enter User Name: ");
                userName = scanner.next();
                user.showApplicationForUser(userName);
                break;
            case 8:
                System.out.println("Exiting Password Manager. Goodbye!");
                break;
            default:
                System.out.println("Invalid choice. Please try again.");
        }


    }


    private static void registerUser() {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter username: ");
        String userName = scanner.next();

        System.out.print("Enter password: ");
        String password = scanner.next();

        System.out.print("Enter email: ");
        String email = scanner.next();

        // Check if the user already exists
        if (!isUserExists(userName)) {
            User newUser = new User(userName, password, email, "user");
            newUser.encryptPassword("AbuNokibKamran"); // Use the same secret key during encryption
            // Write user details to CSV
            writeUserDataToCSV(newUser);
            System.out.println("Registration successful!");
        } else {
            System.out.println("User already exists. Please choose a different username.");
        }
    }


    private static boolean loginUser() {
        Scanner scanner = new Scanner(System.in);


        System.out.print("Enter username: ");
        String userName = scanner.next();

        System.out.print("Enter password: ");
        String password = scanner.next();

        // Check if the entered credentials are valid
        if (isValidUserCredentials(userName, password)) {
            loggedInUserName = userName;
            System.out.println("Login successful!");
            return true;

        } else {
            System.out.println("Invalid username or password. Please try again.");
            return false;
        }

    }


    private static boolean isUserExists(String userName) {
        List<User> users = readUserDataFromCSV();

        for (User user : users) {
            if (user.getUserName().equals(userName)) {
                return true; // User already exists
            }
        }

        return false;
    }

    private static boolean isValidUserCredentials(String userName, String enteredPassword) {
        List<User> users = readUserDataFromCSV();

        for (User user : users) {
            if (user.getUserName().equals(userName)) {
                // Decrypt stored password and compare
                String decryptedPassword = user.decryptPassword("AbuNokibKamran");
                if (decryptedPassword != null && decryptedPassword.equals(enteredPassword)) {
                    return true; // Valid credentials
                }
            }
        }

        return false;
    }


    private static void writeUserDataToCSV(User user) {
        try (Formatter formatter = new Formatter(new FileWriter(CSV_FILE, true))) {
            formatter.format("%s,%s,%s%n", user.getUserName(), user.getEncryptedPassword(), user.getEmail());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private static List<User> readUserDataFromCSV() {
        List<User> users = new ArrayList<>();

        try (Scanner scanner = new Scanner(new File(CSV_FILE))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                String[] parts = line.split(",");
                if (parts.length == 3) {
                    User user = new User(parts[0], parts[1], parts[2], parts[3]);
                    user.setEncryptedPassword(parts[1]); // Set the encrypted password
                    users.add(user);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return users;
    }

    static void showAllUser() {
        List<User> users = readUserDataFromCSV();

        for (User user : users) {
            System.out.println("User: " + user.getUserName() + ", Email: " + user.getEmail());
        }


    }


}