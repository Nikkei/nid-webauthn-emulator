import * as fs from "node:fs";
import * as path from "node:path";

import {
  type PasskeyCredential,
  type PasskeysCredentialsRepository,
  deserializeCredential,
  getRepositoryId,
  serializeCredential,
} from "./credentials-repository";

const CREDENTIALS_DIR = path.join(__dirname, "./credentials");

export class PasskeysCredentialsFileRepository implements PasskeysCredentialsRepository {
  constructor(private readonly credentialsDir: string = CREDENTIALS_DIR) {
    if (!fs.existsSync(credentialsDir)) {
      fs.mkdirSync(credentialsDir);
    }
  }

  saveCredential(credential: PasskeyCredential): void {
    const id = getRepositoryId(credential);
    const filename = path.join(this.credentialsDir, `${id}.json`);
    const serialized = serializeCredential(credential);
    fs.writeFileSync(filename, serialized);
  }

  deleteCredential(credential: PasskeyCredential): void {
    const id = getRepositoryId(credential);
    const filename = path.join(this.credentialsDir, `${id}.json`);
    fs.unlink(filename, (err) => {
      if (err) console.error(err);
    });
  }
  loadCredentials(): PasskeyCredential[] {
    const files = fs.readdirSync(this.credentialsDir);
    return files.flatMap((file) => {
      try {
        const filename = path.join(this.credentialsDir, file);
        const serialized = fs.readFileSync(filename, "utf-8");
        return [deserializeCredential(serialized)];
      } catch {
        return [];
      }
    });
  }
}
