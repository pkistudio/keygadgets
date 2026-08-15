import { initX509Gadgets } from '@pkistudio/x509gadgets/app';
import '@pkistudio/x509gadgets/styles.css';
import { receiveX509GadgetsTransfer } from './x509-transfer';

const app = initX509Gadgets({ mount: '#x509GadgetsViewer' });
receiveX509GadgetsTransfer((bytes, sourceName) => {
  app.loadObject(bytes, sourceName);
});
