# Changelog

All notable changes to Vaultsmith are documented here. Release Please maintains this file from Conventional Commits.

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
