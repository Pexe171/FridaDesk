// Autor: Pexe (instagram David.devloli)
using System.Windows.Controls;

namespace FridaDesk.Wpf.Controls;

public partial class ConsolePanel : UserControl
{
    public ConsolePanel()
    {
        InitializeComponent();
        ConsoleBox.TextChanged += (_, _) => ConsoleBox.ScrollToEnd();
    }
}
