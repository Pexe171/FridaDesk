using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using CommunityToolkit.Mvvm.Input;
using FridaHub.App.Views;

namespace FridaHub.App.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class MainWindowViewModel : ObservableObject
{
    [ObservableProperty]
    private object? currentPage;

    [ObservableProperty]
    private string currentButtonLabel = string.Empty;

    public ICommand NextPage { get; }

    public MainWindowViewModel()
    {
        currentPage = App.Services.GetRequiredService<MainView>();
        currentButtonLabel = "Iniciar";
        NextPage = new RelayCommand(() => { /* navegação futura */ });
    }
}
