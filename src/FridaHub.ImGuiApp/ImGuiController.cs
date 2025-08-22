using System;
using System.Numerics;
using ImGuiNET;
using OpenTK.Graphics.OpenGL4;
using OpenTK.Windowing.Desktop;

namespace FridaHub.ImGuiApp;

// Autor: Pexe (instagram David.devloli)
public class ImGuiController : IDisposable
{
    private int _width;
    private int _height;

    public ImGuiController(int width, int height)
    {
        _width = width;
        _height = height;
        ImGui.CreateContext();
        ImGui.GetIO().Fonts.AddFontDefault();
    }

    public void Update(GameWindow window, float deltaSeconds)
    {
        var io = ImGui.GetIO();
        io.DisplaySize = new Vector2(window.Size.X, window.Size.Y);
        io.DeltaTime = deltaSeconds;
        ImGui.NewFrame();
    }

    public void Render()
    {
        ImGui.Render();
        GL.Viewport(0, 0, _width, _height);
    }

    public void WindowResized(int width, int height)
    {
        _width = width;
        _height = height;
    }

    public void Dispose()
    {
    }
}
