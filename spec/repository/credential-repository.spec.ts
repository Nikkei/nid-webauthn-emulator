import * as fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "@jest/globals";
import { PasskeysCredentialsFileRepository } from "../../src/repository/credentials-file-repository";
import { PasskeysCredentialsMemoryRepository } from "../../src/repository/credentials-memory-repository";
import {
  deserializeCredential,
  type PasskeyDiscoverableCredentialJSON,
  serializeCredential,
} from "../../src/repository/credentials-repository";

describe("Credential Repository Test", () => {
  const testCredentialJSON: PasskeyDiscoverableCredentialJSON = {
    publicKeyCredentialDescriptor: {
      id: "9gd8oypZ_ccpqhk3RBjUp85EOK4NA1wtEkU7zr_BOd8",
      type: "public-key",
      transports: ["usb"],
    },
    publicKeyCredentialSource: {
      type: "public-key",
      id: "9gd8oypZ_ccpqhk3RBjUp85EOK4NA1wtEkU7zr_BOd8",
      privateKey:
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMh82zVqIuCWxqRCVlkDvT0H9-0BoYZlol0AVTa2DDAmhRANCAAQbND1i36p1FOClK5Hn7liDCqpz-_H5Hv3kGEc_uX-wxMoERGk7_fHgm4i5QTq27Dby30eqFPryoKA3cNIOvWqJ",
      rpId: "example.com",
      userHandle: "AQIDBA",
    },
    authenticatorData:
      "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdNAAAAAE5JRC1BVVRILTMxNDE1OTIAIPYHfKMqWf3HKaoZN0QY1KfORDiuDQNcLRJFO86_wTnfpQECAyYgASFYIBs0PWLfqnUU4KUrkefuWIMKqnP78fke_eQYRz-5f7DEIlggygREaTv98eCbiLlBOrbsNvLfR6oU-vKgoDdw0g69aok",
    user: {
      id: "AQIDBA",
      name: "example",
      displayName: "example",
    },
  };

  test("Serialize and Deserialize Test", async () => {
    const deserialized = deserializeCredential(JSON.stringify(testCredentialJSON));
    const serialization = serializeCredential(deserialized);
    const reDeserialized = deserializeCredential(serialization);

    expect(reDeserialized).toEqual(deserialized);
  });

  test("Memory Repository Test", async () => {
    const deserialized = deserializeCredential(JSON.stringify(testCredentialJSON));
    const repository = new PasskeysCredentialsMemoryRepository();
    repository.saveCredential(deserialized);
    const loaded = repository.loadCredentials();

    expect(loaded[0]).toEqual(deserialized);
    expect(loaded.length).toEqual(1);

    repository.deleteCredential(deserialized);
    const reLoaded = repository.loadCredentials();
    expect(reLoaded.length).toEqual(0);
  });

  test("File Repository Test", async () => {
    const FILE_IO_WAIT = 500;
    const deserialized = deserializeCredential(JSON.stringify(testCredentialJSON));
    const TEST_CREDENTIALS_DIR = path.join(__dirname, "test-credentials");
    try {
      fs.rmSync(TEST_CREDENTIALS_DIR, { recursive: true, force: true });
      const repository = new PasskeysCredentialsFileRepository(TEST_CREDENTIALS_DIR);

      repository.saveCredential(deserialized);
      await new Promise((resolve) => setTimeout(resolve, FILE_IO_WAIT));

      const loaded = repository.loadCredentials();
      expect(loaded[0]).toEqual(deserialized);
      expect(loaded.length).toEqual(1);

      repository.deleteCredential(deserialized);
      await new Promise((resolve) => setTimeout(resolve, FILE_IO_WAIT));

      // create dummy file
      fs.writeFileSync(path.join(TEST_CREDENTIALS_DIR, "dummy"), "dummy");

      const reLoaded = repository.loadCredentials();
      expect(reLoaded.length).toEqual(0);
    } finally {
      fs.rmSync(TEST_CREDENTIALS_DIR, { recursive: true, force: true });
    }
  });
});
