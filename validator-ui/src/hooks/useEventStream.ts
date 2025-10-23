import { useEffect, useMemo, useState } from 'react';
import { buildApiUrl, createAuthHeaders } from '../lib/api';

export type EventStreamStatus = 'connecting' | 'open' | 'reconnecting' | 'error';

export interface StreamMessage {
  event?: string;
  data: string;
  id?: string;
}

export interface UseEventStreamOptions<T> {
  parser: (message: StreamMessage) => T | null | undefined;
  maxEvents?: number;
  onEvent?: (event: T) => void;
  reconnect?: boolean;
}

export interface EventStreamState<T> {
  status: EventStreamStatus;
  error?: Error;
  events: T[];
  eventCount: number;
}

function findFrameDelimiter(buffer: string): [index: number, length: number] | null {
  const newlineDelimiter = buffer.indexOf('\n\n');
  const carriageDelimiter = buffer.indexOf('\r\n\r\n');
  if (newlineDelimiter === -1 && carriageDelimiter === -1) {
    return null;
  }
  if (newlineDelimiter === -1) {
    return [carriageDelimiter, 4];
  }
  if (carriageDelimiter === -1) {
    return [newlineDelimiter, 2];
  }
  return newlineDelimiter < carriageDelimiter
    ? [newlineDelimiter, 2]
    : [carriageDelimiter, 4];
}

function parseSseFrame(frame: string): StreamMessage | null {
  const lines = frame.split(/\r?\n/);
  const data: string[] = [];
  let event: string | undefined;
  let id: string | undefined;

  for (const line of lines) {
    if (!line || line.startsWith(':')) {
      continue;
    }
    const separator = line.indexOf(':');
    const field = separator === -1 ? line : line.slice(0, separator);
    const value = separator === -1 ? '' : line.slice(separator + 1).trimStart();
    if (field === 'data') {
      data.push(value);
    } else if (field === 'event') {
      event = value;
    } else if (field === 'id') {
      id = value;
    }
  }

  if (data.length === 0) {
    return null;
  }

  return {
    event,
    id,
    data: data.join('\n'),
  };
}

export function useEventStream<T>(
  path: string,
  { parser, maxEvents = 64, onEvent, reconnect = true }: UseEventStreamOptions<T>,
): EventStreamState<T> {
  const [status, setStatus] = useState<EventStreamStatus>('connecting');
  const [error, setError] = useState<Error | undefined>(undefined);
  const [events, setEvents] = useState<T[]>([]);
  const [eventCount, setEventCount] = useState(0);

  const memoizedOptions = useMemo(
    () => ({ parser, maxEvents, onEvent, reconnect }),
    [parser, maxEvents, onEvent, reconnect],
  );

  useEffect(() => {
    let active = true;
    let retryAttempt = 0;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    const decoder = new TextDecoder('utf-8');

    setStatus('connecting');
    setError(undefined);
    setEvents([]);
    setEventCount(0);

    const processBuffer = (state: { buffer: string }) => {
      let delimiter = findFrameDelimiter(state.buffer);
      while (delimiter) {
        const [index, length] = delimiter;
        const frame = state.buffer.slice(0, index);
        state.buffer = state.buffer.slice(index + length);
        const message = parseSseFrame(frame);
        if (message) {
          try {
            const parsed = memoizedOptions.parser(message);
            if (parsed !== null && parsed !== undefined) {
              memoizedOptions.onEvent?.(parsed);
              if (memoizedOptions.maxEvents > 0) {
                setEvents((prev) => {
                  const next = [...prev, parsed];
                  if (next.length > memoizedOptions.maxEvents) {
                    next.splice(0, next.length - memoizedOptions.maxEvents);
                  }
                  return next;
                });
              }
              setEventCount((count) => count + 1);
            }
          } catch (err) {
            const parsedError = err instanceof Error ? err : new Error(String(err));
            setError(parsedError);
          }
        }
        delimiter = findFrameDelimiter(state.buffer);
      }
    };

    const connect = async () => {
      if (!active) return;
      controller = new AbortController();

      try {
        const response = await fetch(buildApiUrl(path), {
          method: 'GET',
          headers: {
            Accept: 'text/event-stream',
            ...createAuthHeaders(),
          },
          cache: 'no-store',
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Stream request failed: ${response.status} ${response.statusText}`);
        }
        if (!response.body) {
          throw new Error('Event stream response missing body');
        }

        setStatus('open');
        setError(undefined);
        retryAttempt = 0;

        const reader = response.body.getReader();
        const bufferState = { buffer: '' };

        while (active) {
          const { value, done } = await reader.read();
          if (done) {
            bufferState.buffer += decoder.decode();
            processBuffer(bufferState);
            break;
          }
          if (value) {
            bufferState.buffer += decoder.decode(value, { stream: true });
            processBuffer(bufferState);
          }
        }

        if (!active) {
          return;
        }

        throw new Error('Event stream closed');
      } catch (err) {
        if (!active) {
          return;
        }

        const streamError = err instanceof Error ? err : new Error(String(err));
        setError(streamError);

        if (!memoizedOptions.reconnect) {
          setStatus('error');
          return;
        }

        setStatus(retryAttempt === 0 ? 'error' : 'reconnecting');
        retryAttempt += 1;
        const delay = Math.min(30_000, 1_000 * 2 ** (retryAttempt - 1));
        retryTimer = setTimeout(() => {
          if (!active) {
            return;
          }
          setStatus('connecting');
          connect();
        }, delay);
      }
    };

    connect();

    return () => {
      active = false;
      if (retryTimer) {
        clearTimeout(retryTimer);
      }
      controller?.abort();
    };
  }, [path, memoizedOptions]);

  return { status, error, events, eventCount };
}
