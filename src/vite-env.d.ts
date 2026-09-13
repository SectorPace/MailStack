/// <reference types="vite/client" />
declare module '*.css';
declare module 'react-dom/client' {
  import type { ReactNode } from 'react';
  export interface Root { render(children: ReactNode): void; unmount(): void }
  export function createRoot(container: Element | DocumentFragment): Root;
  export function hydrateRoot(container: Element | Document, initialChildren: ReactNode): Root;
}
