import React from 'react';
type AnyProps={children?:React.ReactNode;initial?:unknown;animate?:unknown;exit?:unknown;transition?:unknown;layout?:unknown;whileHover?:unknown;whileTap?:unknown;variants?:unknown;[key:string]:unknown};
const cache=new Map<string,React.ComponentType<AnyProps>>();
function component(tag:string){if(cache.has(tag))return cache.get(tag)!;const C=React.forwardRef<HTMLElement,AnyProps>((props,ref)=>{const {initial,animate,exit,transition,layout,whileHover,whileTap,variants,...dom}=props;return React.createElement(tag,{...dom,ref},props.children as React.ReactNode)});C.displayName=`Motion.${tag}`;cache.set(tag,C);return C}
export const motion=new Proxy({} as Record<string,React.ComponentType<AnyProps>>,{get:(_,tag:string)=>component(tag)});
export function AnimatePresence({children}:{children?:React.ReactNode;mode?:string;initial?:boolean}){return <>{children}</>}
