import type { VaultItem } from './lib/vault';

export type DisplayItem = VaultItem & { demoUrl?: string };
const date = (days: number) => Date.now() - days * 86_400_000;
export const demoItems: DisplayItem[] = [
  { id: 'demo-alps', name: 'A moment in the mountains.jpg', kind: 'photo', mimeType: 'image/jpeg', size: 2841536, createdAt: date(0), updatedAt: date(0), favorite: true, collection: 'Travel', trashed: false, demoUrl: '/demo/mountains.jpg' },
  { id: 'demo-passport', name: 'Travel documents.pdf', kind: 'document', mimeType: 'application/pdf', size: 1245760, createdAt: date(1), updatedAt: date(1), favorite: true, collection: 'Personal', trashed: false, demoUrl: '/demo/travel.pdf' },
  { id: 'demo-note', name: 'A few things to remember', kind: 'note', mimeType: 'text/plain', size: 348, createdAt: date(2), updatedAt: date(2), favorite: false, collection: 'Personal', trashed: false, text: 'A few things to remember\n\nTake the scenic route.\nMake more time for the people you love.\nKeep a little space for the unexpected.\n\nNext adventure\n• Book a cabin in the mountains\n• Pack the camera and a good book\n• Leave the laptop at home\n\nSome things are just for you.' },
  { id: 'demo-coast', name: 'Somewhere by the sea.jpg', kind: 'photo', mimeType: 'image/jpeg', size: 3915776, createdAt: date(3), updatedAt: date(3), favorite: false, collection: 'Travel', trashed: false, demoUrl: '/demo/coast.jpg' },
  { id: 'demo-insurance', name: 'Home insurance.pdf', kind: 'document', mimeType: 'application/pdf', size: 845824, createdAt: date(4), updatedAt: date(4), favorite: false, collection: 'Personal', trashed: false, demoUrl: '/demo/insurance.pdf' },
  { id: 'demo-forest', name: 'The quieter days.jpg', kind: 'photo', mimeType: 'image/jpeg', size: 2134016, createdAt: date(5), updatedAt: date(5), favorite: true, collection: 'Travel', trashed: false, demoUrl: '/demo/forest.jpg' },
  { id: 'demo-work', name: 'The next big idea', kind: 'note', mimeType: 'text/plain', size: 492, createdAt: date(6), updatedAt: date(6), favorite: false, collection: 'Work', trashed: false, text: 'The next big idea\n\nGood ideas need somewhere to grow.\n\nA little notebook for plans, possibilities, and the thoughts that arrive when you least expect them.\n\nStart small. Stay curious. Make something meaningful.' },
  { id: 'demo-record', name: 'Personal records.pdf', kind: 'document', mimeType: 'application/pdf', size: 581632, createdAt: date(7), updatedAt: date(7), favorite: false, collection: 'Personal', trashed: false, demoUrl: '/demo/records.pdf' },
];

export const formatBytes = (bytes: number): string => {
  if (!bytes) return '0 KB';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
};
