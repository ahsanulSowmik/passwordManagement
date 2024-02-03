import java.util.List;

public class Website extends PasswordEntity {
    private String websiteName;
    private String url;

    // Constructor
    public Website(String userName, String password, String websiteName, String url) {
        super(userName, password);
        this.websiteName = websiteName;
        this.url = url;
    }

    // Getter methods specific to Website
    public String getWebsiteName() {
        return websiteName;
    }

    public String getUrl() {
        return url;
    }

    public void setWebsiteName(String websiteName) {
        this.websiteName = websiteName;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    void showWebsitesList(List<Website> websites) {
        System.out.println("List of Websites:");
        for (Website website : websites) {
            System.out.println("Website: " + website.getWebsiteName() + ", URL: " + website.getUrl() +
                    ", Password: " + website.getPassword());
        }
    }
}