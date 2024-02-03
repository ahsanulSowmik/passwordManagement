class Application extends PasswordEntity {
    private String applicationName;

    // Constructor
    public Application(String userName, String password, String applicationName) {
        super(userName, password);
        this.applicationName = applicationName;
    }

    // Getter method specific to Application
    public String getApplicationName() {
        return applicationName;
    }
}