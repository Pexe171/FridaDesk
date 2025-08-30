import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lê o arquivo de configuração JSON e expõe os parâmetros necessários.
 * O formato esperado é:
 * {
 *   "minecraftVersion": "1.21",
 *   "gameDir": "C:/caminho/do/minecraft",
 *   "launcherPath": "C:/Program Files/Minecraft Launcher/MinecraftLauncher.exe",
 *   "baritoneCommand": ".mine diamond_ore"
 * }
 *
 * Autor: Pexe (Instagram @David.devloli)
 */
public class ConfigReader {

    /** Estrutura de dados para manter os parâmetros da configuração. */
    public static class Config {
        public String minecraftVersion;
        public String gameDir;
        public String launcherPath;
        public String baritoneCommand;
    }

    /**
     * Carrega o arquivo de configuração localizado em {@code file}.
     */
    public static Config load(Path file) throws IOException {
        String json = Files.readString(file);
        Config cfg = new Config();
        cfg.minecraftVersion = extract(json, "minecraftVersion");
        cfg.gameDir = extract(json, "gameDir");
        cfg.launcherPath = extract(json, "launcherPath");
        cfg.baritoneCommand = extract(json, "baritoneCommand");
        return cfg;
    }

    /**
     * Extração simples de valores string de um JSON de chave/valor.
     * Este método é básico e serve apenas para o exemplo.
     */
    private static String extract(String json, String key) {
        Pattern p = Pattern.compile("\\\"" + key + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : "";
    }
}
