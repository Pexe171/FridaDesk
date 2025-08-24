using CommunityToolkit.Mvvm.ComponentModel;

namespace FridaDesk.Wpf.ViewModels;

// Autor: Pexe (instagram David.devloli)
public partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private DevicesViewModel devicesViewModel;

    public MainViewModel(DevicesViewModel devicesViewModel)
    {
        this.devicesViewModel = devicesViewModel;
    }
}
