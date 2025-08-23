using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.App.Views;

namespace FridaHub.App.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class MainWindowViewModel : ObservableObject
{
    [ObservableProperty]
    private object? currentPage;

    [ObservableProperty]
    private string currentButtonLabel = "Próxima página";

    private int pageIndex;

    public ICommand NextPage { get; }

    public MainWindowViewModel()
    {
        CurrentPage = new HomeView();
        NextPage = new RelayCommand(GoNext);
    }

    private void GoNext()
    {
        if (pageIndex == 0)
        {
            CurrentPage = new SecondView();
            CurrentButtonLabel = "Voltar";
            pageIndex = 1;
        }
        else
        {
            CurrentPage = new HomeView();
            CurrentButtonLabel = "Próxima página";
            pageIndex = 0;
        }
    }
}
