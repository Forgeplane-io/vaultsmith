# Changelog

All notable changes to Vaultsmith are documented here. Release Please maintains this file from Conventional Commits.

## [0.5.0](https://github.com/Forgeplane-io/vaultsmith/compare/v0.4.0...v0.5.0) (2026-08-14)


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
