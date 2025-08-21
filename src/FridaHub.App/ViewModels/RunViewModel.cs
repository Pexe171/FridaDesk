using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using FridaHub.Core.Models;

namespace FridaHub.App.ViewModels;

public partial class RunViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableCollection<ProcessLine> output = new();
}
