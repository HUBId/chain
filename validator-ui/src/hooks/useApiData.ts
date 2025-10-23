import { useEffect, useState } from 'react';
import { fetchJson } from '../lib/api';

type LoadingState<T> =
  | { status: 'loading'; data: undefined; error: undefined }
  | { status: 'error'; data: undefined; error: Error }
  | { status: 'ready'; data: T; error: undefined };

export function useApiData<T>(path: string) {
  const [state, setState] = useState<LoadingState<T>>({
    status: 'loading',
    data: undefined,
    error: undefined,
  });

  useEffect(() => {
    let active = true;

    setState({ status: 'loading', data: undefined, error: undefined });

    fetchJson<T>(path)
      .then((data) => {
        if (active) {
          setState({ status: 'ready', data, error: undefined });
        }
      })
      .catch((error: Error) => {
        if (active) {
          setState({ status: 'error', data: undefined, error });
        }
      });

    return () => {
      active = false;
    };
  }, [path]);

  return state;
}
