import crypto, { type JsonWebKey, type KeyObject } from "node:crypto";
import EncodeUtils from "../libs/encode-utils";

/** @see https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples */
export abstract class CoseKey {
  constructor(
    public kty: number,
    public alg: number,
  ) {}

  public abstract toBytes(): Uint8Array<ArrayBuffer>;

  public abstract toJwk(): JsonWebKey;

  public toKeyObject(): KeyObject {
    return crypto.createPublicKey({ format: "jwk", key: this.toJwk() });
  }

  public static fromKeyObject(keyObject: KeyObject): CoseKey {
    return CoseKey.fromJwk(keyObject.export({ format: "jwk" }) as JsonWebKey);
  }

  public toDer(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.toKeyObject().export({ format: "der", type: "spki" }));
  }

  public static fromDer(der: Uint8Array<ArrayBuffer>): CoseKey {
    return CoseKey.fromKeyObject(crypto.createPublicKey({ format: "der", type: "spki", key: Buffer.from(der) }));
  }

  public equals(other: CoseKey): boolean {
    return this.toKeyObject().equals(other.toKeyObject());
  }

  public static fromBytes(bytes: Uint8Array<ArrayBuffer>): CoseKey {
    const coseKey = EncodeUtils.decodeCbor<Record<number, unknown>>(bytes);
    switch (coseKey[3]) {
      case -7:
        return CoseKeyP256.fromBytes(bytes);
      case -8:
        return CoseKeyEd25519.fromBytes(bytes);
      case -257:
        return CoseKeyRSA.fromBytes(bytes);
      default:
        throw new Error("Not supported key type");
    }
  }

  public static fromJwk(jwk: JsonWebKey): CoseKey {
    if (jwk.crv === "P-256") return CoseKeyP256.fromJwk(jwk);
    if (jwk.crv === "Ed25519") return CoseKeyEd25519.fromJwk(jwk);
    if (jwk.kty === "RSA") return CoseKeyRSA.fromJwk(jwk);
    throw new Error("Not supported key type");
  }
}

class CoseKeyP256 extends CoseKey {
  constructor(
    public x: Uint8Array<ArrayBuffer>,
    public y: Uint8Array<ArrayBuffer>,
  ) {
    super(2, -7);
  }

  public toBytes(): Uint8Array<ArrayBuffer> {
    const coseKey = {
      1: this.kty,
      3: this.alg,
      [-1]: 1,
      [-2]: this.x,
      [-3]: this.y,
    };
    return EncodeUtils.encodeCbor(coseKey);
  }

  public toJwk(): JsonWebKey {
    return {
      kty: "EC",
      crv: "P-256",
      x: EncodeUtils.encodeBase64Url(this.x),
      y: EncodeUtils.encodeBase64Url(this.y),
    };
  }

  public static fromBytes(bytes: Uint8Array<ArrayBuffer>): CoseKeyP256 {
    const coseKey = EncodeUtils.decodeCbor<Record<number, unknown>>(bytes);
    return new CoseKeyP256(coseKey[-2] as Uint8Array<ArrayBuffer>, coseKey[-3] as Uint8Array<ArrayBuffer>);
  }

  public static fromJwk(jwk: JsonWebKey): CoseKeyP256 {
    return new CoseKeyP256(EncodeUtils.decodeBase64Url(jwk.x as string), EncodeUtils.decodeBase64Url(jwk.y as string));
  }
}

class CoseKeyEd25519 extends CoseKey {
  constructor(public x: Uint8Array<ArrayBuffer>) {
    super(1, -8);
  }

  public toBytes(): Uint8Array<ArrayBuffer> {
    const coseKey = {
      1: this.kty,
      3: this.alg,
      [-1]: 6,
      [-2]: this.x,
    };
    return EncodeUtils.encodeCbor(coseKey);
  }

  public toJwk(): JsonWebKey {
    return {
      kty: "OKP",
      crv: "Ed25519",
      x: EncodeUtils.encodeBase64Url(this.x),
    };
  }

  public static fromBytes(bytes: Uint8Array<ArrayBuffer>): CoseKeyEd25519 {
    const coseKey = EncodeUtils.decodeCbor<Record<number, unknown>>(bytes);
    return new CoseKeyEd25519(coseKey[-2] as Uint8Array<ArrayBuffer>);
  }

  public static fromJwk(jwk: JsonWebKey): CoseKeyEd25519 {
    return new CoseKeyEd25519(EncodeUtils.decodeBase64Url(jwk.x as string));
  }
}

class CoseKeyRSA extends CoseKey {
  constructor(
    public n: Uint8Array<ArrayBuffer>,
    public e: Uint8Array<ArrayBuffer>,
  ) {
    super(3, -257);
  }

  public toBytes(): Uint8Array<ArrayBuffer> {
    const coseKey = {
      1: this.kty,
      3: this.alg,
      [-1]: this.n,
      [-2]: this.e,
    };
    return EncodeUtils.encodeCbor(coseKey);
  }

  public toJwk(): JsonWebKey {
    return {
      kty: "RSA",
      n: EncodeUtils.encodeBase64Url(this.n),
      e: EncodeUtils.encodeBase64Url(this.e),
    };
  }

  public static fromBytes(bytes: Uint8Array<ArrayBuffer>): CoseKeyRSA {
    const coseKey = EncodeUtils.decodeCbor<Record<number, unknown>>(bytes);
    return new CoseKeyRSA(coseKey[-1] as Uint8Array<ArrayBuffer>, coseKey[-2] as Uint8Array<ArrayBuffer>);
  }

  public static fromJwk(jwk: JsonWebKey): CoseKeyRSA {
    return new CoseKeyRSA(EncodeUtils.decodeBase64Url(jwk.n as string), EncodeUtils.decodeBase64Url(jwk.e as string));
  }
}
