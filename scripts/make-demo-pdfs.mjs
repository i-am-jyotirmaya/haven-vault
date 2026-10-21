import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Deliberately fictional, app-owned fixtures. No personal information.
for (const [file, title] of [['travel', 'Travel documents'], ['insurance', 'Home insurance'], ['records', 'Personal records']]) {
  const page = (second = false) => `q
0.99 0.99 0.97 rg 0 0 595 842 re f
0.19 0.31 0.24 rg
BT /F1 26 Tf 55 775 Td (haven.) Tj ET
0.54 0.61 0.47 rg
BT /F1 9 Tf 55 700 Td (PERSONAL ARCHIVE  /  FICTIONAL SAMPLE) Tj ET
0.27 0.37 0.23 rg
BT /F1 31 Tf 55 650 Td (${second ? 'The details, kept together.' : title}) Tj ET
0.55 0.60 0.49 rg
BT /F1 12 Tf 55 618 Td (A place for the things that matter.) Tj ET
0.82 0.86 0.77 RG 55 580 m 540 580 l S
0.39 0.47 0.31 rg
BT /F1 14 Tf 55 540 Td (Your private collection) Tj ET
0.55 0.60 0.49 rg
BT /F1 11 Tf 55 510 Td (This document is a sample for exploring Haven.) Tj 0 -22 Td
(It contains no personal information or real records.) Tj 0 -38 Td
(Your uploaded PDFs are decrypted on your device.) Tj 0 -22 Td
(No external document service receives your files.) Tj ET
0.91 0.93 0.87 rg 55 335 485 65 re f
0.44 0.53 0.36 rg
BT /F1 12 Tf 72 372 Td (Only yours.) Tj 0 -20 Td /F1 9 Tf
(Your memories. Your documents. Your peace of mind.) Tj ET
0.66 0.71 0.59 rg
BT /F1 8 Tf 55 55 Td (HAVEN  /  SAMPLE DOCUMENT) Tj 439 0 Td (${second ? '2' : '1'}) Tj ET
Q`;
  const streams = [page(), page(true)];
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    ...streams.map(stream => `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`),
  ];
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object, i) => { offsets.push(Buffer.byteLength(pdf)); pdf += `${i + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach(offset => { pdf += `${String(offset).padStart(10, '0')} 00000 n \n`; });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  writeFileSync(fileURLToPath(new URL(`../public/demo/${file}.pdf`, import.meta.url)), pdf);
}
