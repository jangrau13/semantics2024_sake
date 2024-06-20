# WISER PDF Annotator

Some PoC of Jan to create a PDF Annotator for a better world.

## How to update
1. make some changes
2. update git like
```console
cd pdf_js
git add .
git commit -m "some message"
git push origin poc
cd ..
git add .
git commit -m "some other message"
git push
```

## How to run

Prerequisite: [Shuttle](https://docs.shuttle.rs/getting-started/installation)

1. run 
```
cd pdf_js
gulp wiser
cd ..
cargo shuttle run --external
```