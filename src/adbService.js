// Autor: Pexe (instagram: @David.devloli)
// Garante uso do adbkit em ambientes diferentes sem `top-level await`
const adbPromise =
  typeof window !== 'undefined' && window.require
    ? Promise.resolve(window.require('adbkit'))
    : import('adbkit').then((m) => m.default);

let clientPromise;

function getClient() {
  if (!clientPromise) {
    clientPromise = adbPromise.then((adb) => adb.createClient());
  }
  return clientPromise;
}

export async function listDevices() {
  const client = await getClient();
  const adb = await adbPromise;
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

export async function connectAdb(host, port = 5555) {
  const client = await getClient();
  return client.connect(host, port);
}

export async function autoConnectEmulators(start = 5555, end = 5585) {
  const client = await getClient();
  for (let port = start; port <= end; port += 2) {
    try {
      await client.connect('127.0.0.1', port);
    } catch (e) {
      // Ignora portas sem emulador
    }
  }
  return listDevices();
}

export async function connectTcpip(id, host, port = 5555) {
  const client = await getClient();
  await client.tcpip(id, port);
  return client.connect(host, port);
}

export async function installApk(id, apkPath) {
  const client = await getClient();
  return client.install(id, apkPath);
}

export async function startLogcat(id) {
  const client = await getClient();
  return client.openLogcat(id);
}

export async function healthCheck(id) {
  const client = await getClient();
  const adb = await adbPromise;
  const stream = await client.shell(id, 'echo OK');
  const output = (await adb.util.readAll(stream)).toString().trim();
  return output === 'OK';
}
