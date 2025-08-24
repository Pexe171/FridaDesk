using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using FridaHub.App.Views;

namespace FridaHub.App.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class MainWindowViewModel : ObservableObject
{
    [ObservableProperty]
    private object? currentPage;

    public MainWindowViewModel()
    {
        currentPage = App.Services.GetRequiredService<MainView>();
    }
}
