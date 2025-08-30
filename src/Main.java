import java.nio.file.Path;

/**
 * Ponto de entrada do aplicativo.
 * Lê a configuração, inicia o Minecraft e envia o comando do Baritone.
 *
 * Autor: Pexe (Instagram @David.devloli)
 */
public class Main {
    public static void main(String[] args) {
        try {
            // Carrega configurações do arquivo config.json
            ConfigReader.Config cfg = ConfigReader.load(Path.of("config.json"));

            // Inicia o launcher do Minecraft
            LauncherHandler launcher = new LauncherHandler(cfg);
            launcher.launch();

            // Executa o comando do Baritone após o carregamento do mundo
            BaritoneCommander commander = new BaritoneCommander(cfg.baritoneCommand);
            commander.execute();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
