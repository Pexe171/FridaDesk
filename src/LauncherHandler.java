import java.io.File;
import java.io.IOException;

/**
 * Responsável por iniciar o launcher do Minecraft usando {@link ProcessBuilder}.
 * Ajuste o caminho do executável conforme necessário.
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
     * parâmetro "gameDir" do arquivo de configuração. Caso o campo
     * {@code launcherPath} esteja vazio, assume-se que o executável
     * "minecraft-launcher" está no PATH do sistema.
     */
    public Process launch() throws IOException {
        String executable = config.launcherPath == null || config.launcherPath.isBlank()
                ? "minecraft-launcher"
                : config.launcherPath;

        ProcessBuilder pb = new ProcessBuilder(executable, "--workDir", config.gameDir,
                "--version", config.minecraftVersion);
        pb.directory(new File(config.gameDir));
        return pb.start();
    }
}
