import java.io.File;
import java.io.IOException;

/**
 * Responsável por iniciar o launcher do Minecraft usando {@link ProcessBuilder}.
 * Ajuste o caminho do executável conforme necessário via `launcherPath` no config.
 *
 * Autor: Pexe (Instagram @David.devloli)
 */
public class LauncherHandler {
    private final ConfigReader.Config config;

    public LauncherHandler(ConfigReader.Config config) {
        this.config = config;
    }

    /**
     * Inicia o launcher do Minecraft. O diretório de trabalho é definido pelo
     * parâmetro "gameDir" do arquivo de configuração.
     */
    public Process launch() throws IOException {
        // Usa o caminho configurado ou assume "minecraft-launcher" no PATH
        String launcher = (config.launcherPath != null && !config.launcherPath.isBlank())
                ? config.launcherPath
                : "minecraft-launcher";
        ProcessBuilder pb = new ProcessBuilder(launcher, "--workDir", config.gameDir,
                "--version", config.minecraftVersion);
        pb.directory(new File(config.gameDir));
        return pb.start();
    }
}
