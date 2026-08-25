# Changelog

All notable changes to Vaultsmith are documented here. Release Please maintains this file from Conventional Commits.

## Unreleased

### Installation and Upgrading

- Proofs are disabled by default. To enable rotation attestations, provision a Secret with the fixed `keyring.json` data key and set `proofs.enabled` plus `proofs.existingSecret`; do not put key material in Helm values or environment variables.
- Proofs use `PUBLIC_BASE_URL` as the issuer and reload a valid changed keyring without restart. A malformed replacement keeps the previous valid keyring active.
- When proofs are disabled, normal encrypt, decrypt, and rotate behavior remains available and no signing Secret is required.

## [0.7.1](https://github.com/Forgeplane-io/vaultsmith/compare/v0.7.0...v0.7.1) (2026-08-25)


### Bug Fixes

* **ci:** refresh embedded frontend entrypoint ([b9b8456](https://github.com/Forgeplane-io/vaultsmith/commit/b9b8456a8e8305300ba96b1c2a82cf2ad3f556a6))
* **ci:** remove embedded frontend diff gate ([aa892c4](https://github.com/Forgeplane-io/vaultsmith/commit/aa892c40f630325b71a38c771ed21c8521dea681))
* **ci:** use root Go version for API contract ([2d68aba](https://github.com/Forgeplane-io/vaultsmith/commit/2d68abad7828ea5ce59f67148a88a49c8763d4de))
* **generate:** preserve IPvFuture URI SANs ([7f53c48](https://github.com/Forgeplane-io/vaultsmith/commit/7f53c487e054fd9fdd2517743174719f459e8b23))


### Refactoring

* **ansiblevault:** share envelope serialization ([9296491](https://github.com/Forgeplane-io/vaultsmith/commit/9296491a03a8045c4fb20ee19062b366c8fed825))
* **attestationkeyring:** share bounded file reader ([f0af3ff](https://github.com/Forgeplane-io/vaultsmith/commit/f0af3ff3e1ab3ce30be39d85b9c5c356b41c6233))
* **frontend:** carry dictionary classification ([2d0f40b](https://github.com/Forgeplane-io/vaultsmith/commit/2d0f40b2f7c7ae98650b3478eb7cfb90e1fc4303))
* **frontend:** centralize module mock methods ([0d9a7c6](https://github.com/Forgeplane-io/vaultsmith/commit/0d9a7c626af3315e2c189bbd98b9e6e159b6700d))
* **frontend:** consolidate active view state ([2ac817f](https://github.com/Forgeplane-io/vaultsmith/commit/2ac817f1b93808be444e0641f83c3ca8c2a2f501))
* **httpapi:** share strict request decoding ([600b3e1](https://github.com/Forgeplane-io/vaultsmith/commit/600b3e101fa008f630c7efc0da3cf0904f82861e))
* **vaultservice:** share attestation readiness checks ([0b80eb0](https://github.com/Forgeplane-io/vaultsmith/commit/0b80eb0f9f7d637b490f3b64ded1e6effc336f82))

## [0.7.0](https://github.com/Forgeplane-io/vaultsmith/compare/v0.6.0...v0.7.0) (2026-08-24)


### Features

* **generate:** add MCP tools and operator UI ([62bf648](https://github.com/Forgeplane-io/vaultsmith/commit/62bf64887f0b97e878f2e5b24474c3933a32ee27))
* **generate:** add private material generator core ([bfaceb8](https://github.com/Forgeplane-io/vaultsmith/commit/bfaceb8566c8221515736df3e6dfdcd7cce9098f))
* **generate:** add sealed generation service and API ([206714b](https://github.com/Forgeplane-io/vaultsmith/commit/206714b4f5d1ad5876b34a3829410684dfc31e7a))


### Bug Fixes

* **attestation:** qualify Helm and operations ([21fe4e4](https://github.com/Forgeplane-io/vaultsmith/commit/21fe4e45b8cbb45e15d08b5b39258b89d3b76ae4))
* **config:** remove duplicate MCPGODEBUG startup check ([7b416db](https://github.com/Forgeplane-io/vaultsmith/commit/7b416dba0abe0a27ed1cd5fc112c61186bd53a47))
* **ui:** keep generate settings compact ([bf03d98](https://github.com/Forgeplane-io/vaultsmith/commit/bf03d98a82c71d073dbcb8f0ac58cf539488c417))
* **ui:** sync embedded frontend entrypoint ([b1c887a](https://github.com/Forgeplane-io/vaultsmith/commit/b1c887a3630615673d155696f5708abb850b773c))

## [0.6.0](https://github.com/Forgeplane-io/vaultsmith/compare/v0.5.0...v0.6.0) (2026-08-15)


### Features

* **attestation:** add keyring lifecycle ([43b1b85](https://github.com/Forgeplane-io/vaultsmith/commit/43b1b85335adc0b877d80f702631d282dea5bf06))
* **attestation:** add MCP and bundled UI integration ([22907db](https://github.com/Forgeplane-io/vaultsmith/commit/22907db1086b9fe700890e71c1be158c403129db))
* **attestation:** add REST service integration ([82ac6c6](https://github.com/Forgeplane-io/vaultsmith/commit/82ac6c60986e85e7d7422ecb204c482b0a699726))
* **attestation:** add rotation attestation core ([8719f8d](https://github.com/Forgeplane-io/vaultsmith/commit/8719f8d59bcc10bd8a3d82c0849400026f9faf8d))


### Bug Fixes

* **attestation:** restrict signing to v1 ([d98c770](https://github.com/Forgeplane-io/vaultsmith/commit/d98c770bd9ccb406dbc98976bf0768862c7f7e8e))
* **attestation:** use fully specified Ed25519 alg ([4305c2e](https://github.com/Forgeplane-io/vaultsmith/commit/4305c2e519ef53c21dd7c1ebc4138ee9ef149f7b))
* **ui:** refresh embedded frontend entrypoint ([c9cbc06](https://github.com/Forgeplane-io/vaultsmith/commit/c9cbc065579469771999310b88cbe25ce34884cd))
* **ui:** sync embedded frontend entrypoint ([bfc828c](https://github.com/Forgeplane-io/vaultsmith/commit/bfc828cb19ee3ad8e4eb9573458d288f969021a5))
* **ui:** unify Verify navigation ([cd81943](https://github.com/Forgeplane-io/vaultsmith/commit/cd819437b0176164767cecf6243df803523f6631))

## [0.5.0](https://github.com/Forgeplane-io/vaultsmith/compare/v0.4.0...v0.5.0) (2026-08-14)


## Installation and Upgrading

- The bundled UI now uses the canonical REST API. Older clients can continue to use `POST /api/v1/operations`.
- Native deployments need OIDC, a public URL, CSRF, profile, policy, and Redis settings. See the deployment guide.
- MCP is off by default.

### Features

* **api:** add contract foundation ([3ff6709](https://github.com/Forgeplane-io/vaultsmith/commit/3ff670935092d98321bffe353c245d90c15cccb4))
* **api:** extract shared vault service ([95ca7c0](https://github.com/Forgeplane-io/vaultsmith/commit/95ca7c01313b23376b689a1cbace7ca5a904b2f3))
* **api:** ship server bridge ([9666ce3](https://github.com/Forgeplane-io/vaultsmith/commit/9666ce3e50cdc5650abda679fafec9ed7c14981e))
* **ui:** use canonical REST operation endpoints ([02685af](https://github.com/Forgeplane-io/vaultsmith/commit/02685afaee23a5f6b92890327f99c27fbf90ba9c))


### Bug Fixes

* **api:** address sequence 3 review blockers ([d98ad60](https://github.com/Forgeplane-io/vaultsmith/commit/d98ad601b2084b87a20ae8c6e1bfbe721535731b))
* **api:** close authentication boundary blockers ([ba174a1](https://github.com/Forgeplane-io/vaultsmith/commit/ba174a19852dde104ba3ce761bbb1b22567efdc7))
* **api:** close remaining review blockers ([4091764](https://github.com/Forgeplane-io/vaultsmith/commit/4091764fa22f5497e723115b593c6568e28026c6))
* **api:** preserve MCP extension metadata ([65b1d2f](https://github.com/Forgeplane-io/vaultsmith/commit/65b1d2fd19d2e8a1c683566874d198da43b12a19))
* **api:** reject malformed origin and endpoint URLs ([042d053](https://github.com/Forgeplane-io/vaultsmith/commit/042d053ebd115c044719362257d21e54b8b16fc7))
* **api:** update vulnerable generator dependency ([776f656](https://github.com/Forgeplane-io/vaultsmith/commit/776f65634ffa77acc487e489c9a712dab786dab2))
* **authn:** isolate JWKS refresh from caller cancellation ([a212bab](https://github.com/Forgeplane-io/vaultsmith/commit/a212bab8a07a7421d8b9eb2c294275e7546f26f5))
* **authn:** retain JWKS unknown-kid throttle ([ba335d3](https://github.com/Forgeplane-io/vaultsmith/commit/ba335d3925190e292153da23daa2fd3d6f632a7e))
* **ci:** harden release bootstrap ([0240d2d](https://github.com/Forgeplane-io/vaultsmith/commit/0240d2db13031178befa316de7b659c5602b002d))
* **ci:** retry GoReleaser bootstrap ([0006bab](https://github.com/Forgeplane-io/vaultsmith/commit/0006bab5a9c167d826153ee27fe01900062b9852))
* **ci:** verify active rollout pods ([61137f0](https://github.com/Forgeplane-io/vaultsmith/commit/61137f0303047483d080a0bd69eb4a943aded32f))
* **ci:** verify release archive members ([02a6ff0](https://github.com/Forgeplane-io/vaultsmith/commit/02a6ff0b4876ae954588bb2a161263c2d3d0072c))
* **ui:** update embedded frontend entrypoint ([022e3c0](https://github.com/Forgeplane-io/vaultsmith/commit/022e3c01ae5e819bd66ef3f597e0eaf5f213f50b))

## [0.4.0](https://github.com/Forgeplane-io/vaultsmith/compare/v0.3.1...v0.4.0) (2026-08-10)


### Features

* **chart:** bundle official Valkey ([8aa4fdb](https://github.com/Forgeplane-io/vaultsmith/commit/8aa4fdb3f525d4481542ca3ef435ff815e42e9bf))


### Bug Fixes

* **chart:** close Valkey storage and ACL contracts ([167b83a](https://github.com/Forgeplane-io/vaultsmith/commit/167b83a69c97c6fd3519dee068a4ae1312b61db1))
* **chart:** harden Valkey rollout and release docs ([0e30103](https://github.com/Forgeplane-io/vaultsmith/commit/0e30103275d9ae021df730032c247062190c8200))
* **ui:** address workbench review feedback ([43f4d21](https://github.com/Forgeplane-io/vaultsmith/commit/43f4d21d547bdfddccd2f4b8611274f0172c2d5c))
* **ui:** tighten workbench spacing ([382391f](https://github.com/Forgeplane-io/vaultsmith/commit/382391fd413fca659154dfe27ae86c361368c23b))


### Refactoring

* **ui:** align Vaultsmith workbench layout ([f163aae](https://github.com/Forgeplane-io/vaultsmith/commit/f163aaedc3425fd71e7e2a2993266304e17e9cf6))

## [0.3.1](https://github.com/Forgeplane-io/vaultsmith/compare/v0.3.0...v0.3.1) (2026-08-10)


### Bug Fixes

* **auth:** bound sign-out and clear sensitive state ([5fc4c14](https://github.com/Forgeplane-io/vaultsmith/commit/5fc4c144bb2ae1747769a5091fef96329d7dffc9))

## [0.3.0](https://github.com/Forgeplane-io/vaultsmith/compare/v0.2.1...v0.3.0) (2026-08-10)


### Features

* **ui:** add Vault ID environment selection ([0e45fb5](https://github.com/Forgeplane-io/vaultsmith/commit/0e45fb55dad38e80bec6de78d6df59b77b25843e))

## [0.2.1](https://github.com/Forgeplane-io/vaultsmith/compare/v0.2.0...v0.2.1) (2026-08-09)


### Bug Fixes

* harden bootstrap readiness handling ([02137c4](https://github.com/Forgeplane-io/vaultsmith/commit/02137c4a7223e7e5d215d8784c2f7e5d14565d96))

## [0.2.0](https://github.com/Forgeplane-io/vaultsmith/compare/v0.1.1...v0.2.0) (2026-08-09)


### Features

* **auth:** add native OIDC authentication ([66a1a64](https://github.com/Forgeplane-io/vaultsmith/commit/66a1a643a3bcdebb75dfd3372290019d48f150e5))
* **authz:** add permission-aware workbench ([8b00253](https://github.com/Forgeplane-io/vaultsmith/commit/8b002538d285292fda883341128cf3dfe6acc17d))


### Bug Fixes

* **auth:** close security review gaps ([a81a6fb](https://github.com/Forgeplane-io/vaultsmith/commit/a81a6fbb0b10959b261ff89b6e094bb099789fc4))
* **auth:** close session and OIDC security gaps ([46fa987](https://github.com/Forgeplane-io/vaultsmith/commit/46fa987b98cfd913221e192ec7f74fc67512fa01))
* **auth:** harden session fencing and deployment validation ([94431e7](https://github.com/Forgeplane-io/vaultsmith/commit/94431e7be4409982497100965da7ec0b0e87177b))
* **auth:** skip CSRF in off mode ([f398119](https://github.com/Forgeplane-io/vaultsmith/commit/f398119a918cf47278bbcacd804a22602874305e))
* harden chart CI and network policy rendering ([4877140](https://github.com/Forgeplane-io/vaultsmith/commit/48771408dced49981ad347f7c8aaba3bd37da55b))


### Refactoring

* **authn:** simplify session lock bookkeeping ([7ae5c20](https://github.com/Forgeplane-io/vaultsmith/commit/7ae5c202ba1a97fd8d3b93516a6ea2d540f26e0e))
* **auth:** reduce duplicate auth setup ([12b326d](https://github.com/Forgeplane-io/vaultsmith/commit/12b326d2d7459a3cb135e9476f8ab871a72de9e7))
* **auth:** reduce native auth surface ([eeddf27](https://github.com/Forgeplane-io/vaultsmith/commit/eeddf277e5aed24483cddcd139c4e18e57a21cce))
* **auth:** reduce native authentication surface ([475274a](https://github.com/Forgeplane-io/vaultsmith/commit/475274a1e4bb9c3d60f8439388ed853fcd8ddf82))
* **auth:** remove redundant native auth paths ([93a0b90](https://github.com/Forgeplane-io/vaultsmith/commit/93a0b90666379d00db53acffb4bab07de60fab5d))
* **auth:** simplify native auth branches ([b69fe94](https://github.com/Forgeplane-io/vaultsmith/commit/b69fe94e81ced86c710ec6b850ebc8b31d170ea9))
* **auth:** simplify native auth verification ([09bd590](https://github.com/Forgeplane-io/vaultsmith/commit/09bd59099986ff1be35e9c99ea45996c2a687c86))
* **config:** remove redundant auth loader wrapper ([427bc11](https://github.com/Forgeplane-io/vaultsmith/commit/427bc113ac6b7c0cf05f9cd780b42681d4f2feef))
* **httpapi:** remove dead constructor wrapper ([a094eee](https://github.com/Forgeplane-io/vaultsmith/commit/a094eee659e77184b85a9176facbe8259c7c1c63))
* **web:** remove dead API helpers ([98b5e68](https://github.com/Forgeplane-io/vaultsmith/commit/98b5e6850d13ff5eef9c35c0348ac920fcef55de))
* **web:** remove no-op scaffold test ([b3c2154](https://github.com/Forgeplane-io/vaultsmith/commit/b3c2154e1b25badcc5dad893b7ceb25a0d830fe9))

## [0.1.1](https://github.com/Forgeplane-io/vaultsmith/compare/v0.1.0...v0.1.1) (2026-08-05)


### Bug Fixes

* **chart:** make NetworkPolicy opt-in by default ([ae3fb57](https://github.com/Forgeplane-io/vaultsmith/commit/ae3fb57c63570086c4550cbffebbffc10d91302e))

## 0.1.0 (2026-08-04)


### Features

* polish Vaultsmith UI and add logo ([1aef905](https://github.com/Forgeplane-io/vaultsmith/commit/1aef9056c89b408eb4219cbda87f82776a5ed3f4))
* polish Vaultsmith UI and add logo ([c0e30bf](https://github.com/Forgeplane-io/vaultsmith/commit/c0e30bfa6c66ad1412ae0df17ad0413aae781634))
* **release:** prepare Vaultsmith public release ([31537c5](https://github.com/Forgeplane-io/vaultsmith/commit/31537c55c680bc4f53d5a0eda67cf3cd3b73e388))
* sync upstream paste and deployment hardening ([5f32c0d](https://github.com/Forgeplane-io/vaultsmith/commit/5f32c0d7e00e6320dd0eeb67efa918d42eed2082))


### Bug Fixes

* harden cancellation and release CI ([ba3e43e](https://github.com/Forgeplane-io/vaultsmith/commit/ba3e43e0ea32cef76d24f0273ad2606cdc1a952c))

## [Unreleased]
