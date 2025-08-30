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
     * parâmetro "gameDir" do arquivo de configuração.
     */
    public Process launch() throws IOException {
        // Aqui assumimos que o executável "minecraft-launcher" está no PATH ou
        // localizado dentro do diretório do jogo. Modifique se necessário.
        ProcessBuilder pb = new ProcessBuilder("minecraft-launcher", "--workDir", config.gameDir,
                "--version", config.minecraftVersion);
        pb.directory(new File(config.gameDir));
        return pb.start();
    }
}
