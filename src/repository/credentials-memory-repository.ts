import {
  type PasskeyCredential,
  type PasskeysCredentialsRepository,
  deserializeCredential,
  getRepositoryId,
  serializeCredential,
} from "./credentials-repository";

export class PasskeysCredentialsMemoryRepository implements PasskeysCredentialsRepository {
  private readonly credentials: Map<string, string> = new Map();

  saveCredential(credential: PasskeyCredential): void {
    const id = getRepositoryId(credential);
    const serialized = serializeCredential(credential);
    this.credentials.set(id, serialized);
  }

  deleteCredential(credential: PasskeyCredential): void {
    const id = getRepositoryId(credential);
    this.credentials.delete(id);
  }

  loadCredentials(): PasskeyCredential[] {
    return Array.from(this.credentials.values()).map((serialized) => deserializeCredential(serialized));
  }
}
