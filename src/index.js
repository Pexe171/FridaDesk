export function soma(a, b) {
  return a + b;
}

export { Database } from './db.js';

if (process.env.NODE_ENV !== 'test') {
  console.log('FridaDesk em execução');
}
