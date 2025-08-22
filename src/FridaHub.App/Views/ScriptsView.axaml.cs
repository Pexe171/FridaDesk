using Avalonia.Controls;
using Avalonia.Interactivity;
using FridaHub.App.ViewModels;
using System;
using System.Linq;
using System.Collections.Generic;
using Avalonia.VisualTree;

namespace FridaHub.App.Views;

public partial class ScriptsView : UserControl
{
    public ScriptsView()
    {
        InitializeComponent();
    }

    public ScriptsView(ScriptsViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }

    private async void OnAddLocalScript(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ScriptsViewModel vm) return;

        var window = this.GetVisualRoot() as Window;
        if (window is null) return;

        var ofd = new OpenFileDialog
        {
            AllowMultiple = false,
            Filters =
            {
                new FileDialogFilter { Name = "Scripts", Extensions = { "js" } }
            }
        };

        var paths = await ofd.ShowAsync(window);
        var path = paths?.FirstOrDefault();
        if (string.IsNullOrEmpty(path)) return;

        var titleDialog = new TextInputDialog();
        titleDialog.SetPrompt("Título do script");
        var title = await titleDialog.ShowDialog<string?>(window);
        if (string.IsNullOrWhiteSpace(title)) return;

        var tagsDialog = new TextInputDialog();
        tagsDialog.SetPrompt("Tags (separadas por vírgula)");
        var tagsText = await tagsDialog.ShowDialog<string?>(window);
        var tags = tagsText?.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim()).Where(t => t.Length > 0).ToList() ?? new List<string>();

        await vm.AddLocalScriptAsync(path, title!, tags);
    }
}
