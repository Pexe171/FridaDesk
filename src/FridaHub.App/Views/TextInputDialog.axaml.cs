using Avalonia.Controls;
using Avalonia.Interactivity;

namespace FridaHub.App.Views;

public partial class TextInputDialog : Window
{
    public string? Result { get; private set; }

    public TextInputDialog()
    {
        InitializeComponent();
    }

    public void SetPrompt(string text) => PromptText.Text = text;

    private void OnOk(object? sender, RoutedEventArgs e)
    {
        Result = InputBox.Text;
        Close(Result);
    }
}
