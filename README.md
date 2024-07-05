# SAKE

A Semantic Authoring and Annotation Tool for Knowledge Extraction

Built with [pdf.js](https://mozilla.github.io/pdf.js/) and [AtomicData](https://atomicdata.dev/)

## How to run

Prerequisite: [Shuttle](https://docs.shuttle.rs/getting-started/installation), a SECRETS.toml (see [Example](example.Secrets.toml)), an [AtomicData](https://atomicdata.dev/) backend server.

1. run 
```
cd pdf_js
gulp wiser
cd ..
cargo shuttle run --external
```