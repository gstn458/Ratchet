import { useEffect } from 'react';

export function Login({ data }: { data: ArrayBuffer }) {
  useEffect(() => {
    window.crypto.subtle.digest('SHA-1', data);
    crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  }, [data]);
  return <form><input type="password" /></form>;
}
