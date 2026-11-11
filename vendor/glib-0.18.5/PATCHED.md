# glib 0.18.5, patched

This is the crates.io release of `glib` 0.18.5, unchanged except for one call in
`src/variant_iter.rs` (`VariantStrIter::impl_get`). The out-argument passed to
`g_variant_get_child` is now `&mut p` instead of `&p`.

- Advisory: RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g (unsound, can dereference NULL).
- Upstream fix: https://github.com/gtk-rs/gtk-rs-core/pull/1343, released in glib 0.20.0.
- No 0.18.x release carries it. Tauri 2 pins gtk 0.18 on Linux, and gtk 0.18 requires
  glib ^0.18, so moving to 0.20 is not possible from here.

It is wired in through `[patch.crates-io]` in the workspace `Cargo.toml`. Remove the
patch and this directory once tauri moves to gtk4 / glib >= 0.20.
