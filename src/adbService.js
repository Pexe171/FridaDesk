// Autor: Pexe (instagram: @David.devloli)
import adb from 'adbkit';

const client = adb.createClient();

export async function listDevices() {
  const devices = await client.listDevices();
  return Promise.all(
    devices.map(async (device) => {
      let model = 'desconhecido';
      try {
        const stream = await client.shell(
          device.id,
          'getprop ro.product.model'
        );
        model = (await adb.util.readAll(stream)).toString().trim();
      } catch (e) {
        // Ignora erros ao obter modelo
      }
      return { id: device.id, type: device.type, model };
    })
  );
}

export async function connectTcpip(id, host, port = 5555) {
  await client.tcpip(id, port);
  return client.connect(host, port);
}

export function installApk(id, apkPath) {
  return client.install(id, apkPath);
}

export function startLogcat(id) {
  return client.openLogcat(id);
}

export async function healthCheck(id) {
  const stream = await client.shell(id, 'echo OK');
  const output = (await adb.util.readAll(stream)).toString().trim();
  return output === 'OK';
}
