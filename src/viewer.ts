import derEditorIconUrl from '@pkistudio/dereditor/dereditor.ico';
import { mountDerEditor } from './dereditor-adapter';

const mount = document.querySelector<HTMLElement>('#dereditorViewer');
if (!mount) throw new Error('Standalone DerEditor mount was not found.');

let icon = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
if (!icon) {
  icon = document.createElement('link');
  icon.rel = 'icon';
  document.head.append(icon);
}
icon.href = derEditorIconUrl;

mountDerEditor(mount, {
  editable: true,
  fullscreen: true,
  newWindowUrl: window.location.href
});
