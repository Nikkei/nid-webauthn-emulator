# テスト用 Passkeys Authenticator デモ

## 概要

Passkeys Authenticator の[エミュレータ](https://github.com/Nikkei/nid-passkeys-authenticator-demo/blob/main/src/passkeys-test-authenticator.ts)および <https://webauthn.io/> でのデモアプリです。

## 実行方法

<https://webauthn.io/> でパスキーの登録、および登録したパスキーでのログインを行います。

```bash
git clone
cd nid-passkeys-authenticator-demo
npm install
npm test
```

## 実行例

```bash
% npm test

> nid-fido2-authenticator@0.0.0 test
> jest

  console.log
    Registration options {
      publicKey: {
        rp: { name: 'webauthn.io', id: 'webauthn.io' },
        user: { id: [ArrayBuffer], name: 'test-user', displayName: 'test-user' },
        challenge: ArrayBuffer {
          [Uint8Contents]: <ce a9 99 6c 87 2f 42 89 7b 3a 38 a9 66 30 2d eb ce 84 42 20 5a 74 17 07 46 29 33 28 8d aa c6 cd 69 4e 81 75 3e a5 8a ac 01 f5 ba ca 89 91 c9 85 52 46 5b f7 67 e2 f7 04 6e fc b1 65 fe 65 ab 70>,
          byteLength: 64
        },
        pubKeyCredParams: [ [Object], [Object] ],
        timeout: 60000,
        excludeCredentials: [
          [Object], [Object], [Object],
          [Object], [Object], [Object],
          [Object], [Object], [Object],
          [Object], [Object], [Object],
          [Object], [Object], [Object],
          [Object], [Object], [Object],
          [Object]
        ],
        authenticatorSelection: {
          residentKey: 'preferred',
          requireResidentKey: false,
          userVerification: 'preferred'
        },
        attestation: 'none',
        extensions: { credProps: true }
      }
    }

      at src/test-utils/passkeys-ceremony.ts:16:11

  console.log
    Registration credential {
      id: 's9xEwXNdArtolUBBzM7hYwByQGiLZgmSD3jHcnbOcLk',
      rawId: 's9xEwXNdArtolUBBzM7hYwByQGiLZgmSD3jHcnbOcLk',
      response: {
        clientDataJSON: 'eyJjaGFsbGVuZ2UiOiJ6cW1aYkljdlFvbDdPamlwWmpBdDY4NkVRaUJhZEJjSFJpa3pLSTJxeHMxcFRvRjFQcVdLckFIMXVzcUprY21GVWtaYjkyZmk5d1J1X0xGbF9tV3JjQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ',
        authenticatorData: 'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBNAAAAAI7ftrtAE8SkbJa5Y0ATgT8AILPcRMFzXQK7aJVAQczO4WMAckBoi2YJkg94x3J2znC5pQECAyYgASFYIEAPtJpU3m4u7W6scsfNXF-HTWK9krol636dGimiwTrCIlggKHcg_sVtJa0c9P8cYk_5E2KodKuJEGtCeGlLO1ZVo7Y',
        transports: [ 'usb' ],
        publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQA-0mlTebi7tbqxyx81cX4dNYr2SuiXrfp0aKaLBOsIodyD-xW0lrRz0_xxiT_kTYqh0q4kQa0J4aUs7VlWjtg',
        publicKeyAlgorithm: -7,
        attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBNAAAAAI7ftrtAE8SkbJa5Y0ATgT8AILPcRMFzXQK7aJVAQczO4WMAckBoi2YJkg94x3J2znC5pQECAyYgASFYIEAPtJpU3m4u7W6scsfNXF-HTWK9krol636dGimiwTrCIlggKHcg_sVtJa0c9P8cYk_5E2KodKuJEGtCeGlLO1ZVo7Y'
      },
      authenticatorAttachment: undefined,
      clientExtensionResults: { credProps: { rk: true } },
      type: 'public-key'
    }

      at src/test-utils/passkeys-ceremony.ts:20:11

  console.log
    Registration verification completed

      at src/test-utils/passkeys-ceremony.ts:22:11

  console.log
    Authentication options {
      publicKey: {
        challenge: ArrayBuffer {
          [Uint8Contents]: <e5 d7 5e 65 c0 b8 1d e9 98 77 4c 0e 27 ce 41 5f 4a 08 2f 59 61 cd df 91 63 c7 a7 bf 19 6a 21 64 8d cf b7 5e be 30 6b 00 7b 75 55 c6 59 8d 58 f1 1f 9a 1e d5 0d 8e 84 43 a9 06 e5 d7 9d b3 7a 11>,
          byteLength: 64
        },
        timeout: 60000,
        rpId: 'webauthn.io',
        allowCredentials: [],
        userVerification: 'preferred',
        extensions: undefined
      }
    }

      at src/test-utils/passkeys-ceremony.ts:31:11

  console.log
    Authentication credential {
      id: 's9xEwXNdArtolUBBzM7hYwByQGiLZgmSD3jHcnbOcLk',
      rawId: 's9xEwXNdArtolUBBzM7hYwByQGiLZgmSD3jHcnbOcLk',
      response: {
        clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNWRkZVpjQzRIZW1ZZDB3T0o4NUJYMG9JTDFsaHpkLVJZOGVudnhscUlXU056N2RldmpCckFIdDFWY1paalZqeEg1b2UxUTJPaEVPcEJ1WFhuYk42RVEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ',
        authenticatorData: 'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBNAAAAAI7ftrtAE8SkbJa5Y0ATgT8AILPcRMFzXQK7aJVAQczO4WMAckBoi2YJkg94x3J2znC5pQECAyYgASFYIEAPtJpU3m4u7W6scsfNXF-HTWK9krol636dGimiwTrCIlggKHcg_sVtJa0c9P8cYk_5E2KodKuJEGtCeGlLO1ZVo7Y',
        signature: 'MEYCIQCE2F79tVvM8yGc5InLEBhXtM3JQQkLafKJxiYVrzNdbAIhAPi6xxuadB7lXDpoAFwmNXpom-thkzZEz76dDOrzO9hA',
        userHandle: undefined
      },
      authenticatorAttachment: undefined,
      clientExtensionResults: { credProps: { rk: true } },
      type: 'public-key'
    }

      at src/test-utils/passkeys-ceremony.ts:35:11

  console.log
    Authentication verification completed

      at src/test-utils/passkeys-ceremony.ts:37:11

 PASS  src/test.spec.ts
  webauthn.io を利用した Passkeys の登録とログイン
    ✓ Registration Ceremony and Authentication Ceremony (2004 ms)

Test Suites: 1 passed, 1 total
Tests:       1 passed, 1 total
Snapshots:   0 total
Time:        2.503 s, estimated 3 s
Ran all test suites.
```

[パスキー API インターフェース](src/test-utils/passkeys-api-client.ts) の実装を行うことで、その他のサイトのパスキーにも対応可能です。

## 参考資料

このコードは [Bitwarden](https://github.com/bitwarden/clients) (GPL 3.0) のコードを参考または一部利用しています。ライセンスに注意して利用してください。
