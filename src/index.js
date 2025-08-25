export function soma(a, b) {
  return a + b;
}

export { Database } from './db.js';
export { ScriptsService } from './scriptsService.js';
export { NetworkCapture } from './networkCapture.js';
export {
  listDevices,
  connectAdb,
  autoConnectEmulators,
  connectTcpip,
  installApk,
  startLogcat,
  healthCheck,
} from './adbService.js';

if (process.env.NODE_ENV !== 'test') {
  console.log('FridaDesk em execução');
}
