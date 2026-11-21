// Mocha inside the VS Code extension host; ASENT_SUITE picks trusted.test.js or untrusted.test.js.
import * as path from "path";
import Mocha from "mocha";

export function run(): Promise<void> {
  const mocha = new Mocha({ ui: "bdd", timeout: 30000, color: false });
  mocha.addFile(path.join(__dirname, `${process.env.ASENT_SUITE}.test.js`));
  return new Promise((resolve, reject) => {
    mocha.run((failures) => (failures ? reject(new Error(`${failures} extension test(s) failed`)) : resolve()));
  });
}
