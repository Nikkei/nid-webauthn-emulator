import * as fs from "node:fs";
import * as path from "node:path";

import {
  type PasskeyDiscoverableCredential,
  type PasskeysCredentialsRepository,
  deserializeCredential,
  getRepositoryId,
  serializeCredential,
} from "./credentials-repository";

const CREDENTIALS_DIR = path.join(__dirname, "./credentials");

export class PasskeysCredentialsFileRepository implements PasskeysCredentialsRepository {
  constructor(private readonly credentialsDir: string = CREDENTIALS_DIR) {
    fs.mkdirSync(credentialsDir, { recursive: true });
  }

  saveCredential(credential: PasskeyDiscoverableCredential): void {
    const id = getRepositoryId(credential);
    const filename = path.join(this.credentialsDir, `${id}.json`);
    const serialized = serializeCredential(credential);
    fs.writeFileSync(filename, serialized);
  }

  deleteCredential(credential: PasskeyDiscoverableCredential): void {
    const id = getRepositoryId(credential);
    const filename = path.join(this.credentialsDir, `${id}.json`);
    fs.unlink(filename, () => {});
  }
  loadCredentials(): PasskeyDiscoverableCredential[] {
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
