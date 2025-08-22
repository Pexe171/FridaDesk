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
    private int _fontTexture;

    public ImGuiController(int width, int height)
    {
        _width = width;
        _height = height;
        ImGui.CreateContext();
        var io = ImGui.GetIO();
        io.Fonts.AddFontDefault();
        io.Fonts.GetTexDataAsRGBA32(out IntPtr pixels, out int fontWidth, out int fontHeight, out _);
        _fontTexture = GL.GenTexture();
        GL.BindTexture(TextureTarget.Texture2D, _fontTexture);
        GL.TexParameter(TextureTarget.Texture2D, TextureParameterName.TextureMinFilter, (int)TextureMinFilter.Linear);
        GL.TexParameter(TextureTarget.Texture2D, TextureParameterName.TextureMagFilter, (int)TextureMagFilter.Linear);
        GL.TexImage2D(TextureTarget.Texture2D, 0, PixelInternalFormat.Rgba, fontWidth, fontHeight, 0,
            PixelFormat.Rgba, PixelType.UnsignedByte, pixels);
        io.Fonts.SetTexID((IntPtr)_fontTexture);
        io.Fonts.ClearTexData();
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
        if (_fontTexture != 0)
            GL.DeleteTexture(_fontTexture);
    }
}
