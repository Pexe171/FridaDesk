// Autor: Pexe (instagram: @David.devloli)
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

// Desativa aceleração de hardware para evitar problemas com GPU
app.disableHardwareAcceleration();

ipcMain.handle('devices:list', async () => {
  const { listDevices, autoConnectEmulators } = await import('./src/adbService.js');
  await autoConnectEmulators().catch(() => {});
  return listDevices();
});

ipcMain.handle('adb:connect', async (_event, ip, port) => {
  const { connectAdb } = await import('./src/adbService.js');
  await connectAdb(ip, port);
});

ipcMain.handle('frida:ensure', async (_event, id) => {
  const { ensureFrida } = await import('./src/fridaService.js');
  await ensureFrida(id);
});

ipcMain.handle('frida:isRunning', async (_event, id) => {
  const { isFridaRunning } = await import('./src/fridaService.js');
  return isFridaRunning(id);
});

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  win.loadFile(path.join(__dirname, 'dist/index.html'));
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
