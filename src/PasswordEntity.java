public class PasswordEntity {

    private String userName;
    private String password;


    // Constructor
    public PasswordEntity(String userName, String password) {
        this.userName = userName;
        this.password = password;

    }

    // Getter methods
    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }


}
