# Roadmap

## Architecture

* main.rs: entrypoint
* cli.rs: CLI parsing
* model.rs
* error.rs
* fetch.rs: download lists from URL

## 1. CLI

* [x] 1.1 async main using tokio
* [x] 1.2 parse CLI

## Unsorted

* [ ] download & process multiple lists using rayon
* [ ] zstd compress to reduce RAM usage for sorting and deduplication?
* [ ] extract dgaard structs into a lib so it can be used for adblockptimize?
