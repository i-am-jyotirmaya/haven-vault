# Third-party notices

The MIT license applies to Haven's original source, documentation, and original sample PDFs. It does not relicense third-party material.

## Demo photographs

`public/demo/mountains.jpg`, `public/demo/coast.jpg`, and `public/demo/forest.jpg` were sourced from Unsplash and are distributed under the [Unsplash License](https://unsplash.com/license), not MIT. That license permits broad use and redistribution, subject to restrictions including selling unmodified images and building a competing image service. Original photographer attribution was not retained in this initial project; do not invent attribution or claim ownership.

Photographs are bundled locally, so opening the vault does not fetch them from an external image service.

## Dependencies

React, Vite, Firebase, SimpleWebAuthn, PDF.js, Lucide, and other dependencies retain their upstream licenses. Versions are recorded in `pnpm-lock.yaml` and `functions/package-lock.json`; packages contain their license notices. Preserve applicable notices when redistributing builds. PDF.js and its worker are bundled for local preview rendering.
