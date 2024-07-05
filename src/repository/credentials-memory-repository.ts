import {
  type PasskeyDiscoverableCredential,
  type PasskeysCredentialsRepository,
  deserializeCredential,
  getRepositoryId,
  serializeCredential,
} from "./credentials-repository";

export class PasskeysCredentialsMemoryRepository implements PasskeysCredentialsRepository {
  private readonly credentials: Map<string, string> = new Map();

  saveCredential(credential: PasskeyDiscoverableCredential): void {
    const id = getRepositoryId(credential);
    const serialized = serializeCredential(credential);
    this.credentials.set(id, serialized);
  }

  deleteCredential(credential: PasskeyDiscoverableCredential): void {
    const id = getRepositoryId(credential);
    this.credentials.delete(id);
  }

  loadCredentials(): PasskeyDiscoverableCredential[] {
    return Array.from(this.credentials.values()).map((serialized) => deserializeCredential(serialized));
  }
}
