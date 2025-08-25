// Autor: Pexe (instagram: @David.devloli)
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('myAPI', {
  listDevices: () => ipcRenderer.invoke('devices:list'),
  connectAdb: (ip, port) => ipcRenderer.invoke('adb:connect', ip, port),
  ensureFrida: (id) => ipcRenderer.invoke('frida:ensure', id),
  isFridaRunning: (id) => ipcRenderer.invoke('frida:isRunning', id),
});
