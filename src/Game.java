public class Game extends PasswordEntity {
    private String gameName;
    private String developerName;

    // Constructor
    public Game(String userName, String password, String gameName, String developerName) {
        super(userName, password);
        this.gameName = gameName;
        this.developerName = developerName;
    }

    // Getter methods specific to Game
    public String getGameName() {
        return gameName;
    }

    public String getDeveloperName() {
        return developerName;
    }
}