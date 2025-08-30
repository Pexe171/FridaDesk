import java.awt.AWTException;
import java.awt.Robot;
import java.awt.event.KeyEvent;

/**
 * Envia comandos ao chat do Minecraft para controlar o Baritone.
 *
 * Autor: Pexe (Instagram @David.devloli)
 */
public class BaritoneCommander {
    private final String command;

    public BaritoneCommander(String command) {
        this.command = command;
    }

    /**
     * Aguarda alguns segundos e envia o comando configurado ao chat.
     * Ajuste o tempo de espera conforme necessário para garantir que o mundo já carregou.
     */
    public void execute() throws AWTException, InterruptedException {
        // Tempo padrão de espera: 15s
        Thread.sleep(15000);
        Robot robot = new Robot();

        // Abre o chat com a tecla "T"
        robot.keyPress(KeyEvent.VK_T);
        robot.keyRelease(KeyEvent.VK_T);
        Thread.sleep(500);

        // Digita o comando caracter por caracter
        for (char c : command.toCharArray()) {
            typeChar(robot, c);
            Thread.sleep(20); // leve atraso para evitar perda de caracteres
        }

        // Pressiona ENTER para enviar
        robot.keyPress(KeyEvent.VK_ENTER);
        robot.keyRelease(KeyEvent.VK_ENTER);
    }

    /**
     * Converte um caractere em um evento de teclado.
     * Esta implementação cobre apenas caracteres comuns usados em comandos.
     */
    private void typeChar(Robot robot, char c) {
        int keyCode = KeyEvent.getExtendedKeyCodeForChar(c);
        if (keyCode == KeyEvent.VK_UNDEFINED) {
            return; // ignora caracteres desconhecidos
        }

        boolean shift = Character.isUpperCase(c) || "_?!:@#%&*()<>|".indexOf(c) >= 0;
        if (shift) {
            robot.keyPress(KeyEvent.VK_SHIFT);
        }
        robot.keyPress(keyCode);
        robot.keyRelease(keyCode);
        if (shift) {
            robot.keyRelease(KeyEvent.VK_SHIFT);
        }
    }
}
