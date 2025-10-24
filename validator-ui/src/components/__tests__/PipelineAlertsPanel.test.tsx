import { act, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { PipelineAlertsPanel } from '../PipelineAlertsPanel';
import type { PipelineEvent, PipelineErrorPayload } from '../../types';
import type {
  EventStreamState,
  UseEventStreamOptions,
} from '../../hooks/useEventStream';

const useEventStreamMock = vi.fn<
  (path: string, options: UseEventStreamOptions<PipelineEvent>) => EventStreamState<PipelineEvent>
>();

vi.mock('../../hooks/useEventStream', () => ({
  useEventStream: (...args: Parameters<typeof useEventStreamMock>) =>
    useEventStreamMock(...args),
}));

describe('PipelineAlertsPanel', () => {
  let capturedHandler: ((event: PipelineEvent) => void) | undefined;

  beforeEach(() => {
    capturedHandler = undefined;
    useEventStreamMock.mockReset();
    useEventStreamMock.mockImplementation((_path, options) => {
      capturedHandler = options.onEvent;
      return {
        status: 'open',
        error: undefined,
        events: [],
        eventCount: 0,
      };
    });
  });

  it('renders alerts when the event stream reports an error', () => {
    const observedAt = Date.UTC(2024, 0, 1, 12, 34, 56);
    const payload: PipelineErrorPayload = {
      stage: 'bft_finalised',
      height: 128,
      round: 5,
      block_hash: 'ffffffffffffffffffffffffffffffff',
      message: 'Simulated pipeline failure',
      observed_at_ms: observedAt,
    };

    render(<PipelineAlertsPanel />);

    expect(useEventStreamMock).toHaveBeenCalledWith(
      '/wallet/pipeline/stream',
      expect.objectContaining({ onEvent: expect.any(Function) }),
    );

    expect(screen.getByText('No pipeline issues detected.')).toBeInTheDocument();

    act(() => {
      capturedHandler?.({ type: 'error', error: payload });
    });

    expect(screen.queryByText('No pipeline issues detected.')).toBeNull();
    expect(screen.getByText('Simulated pipeline failure')).toBeInTheDocument();
    expect(screen.getByText('Bft Finalised')).toBeInTheDocument();
    expect(screen.getByText('128')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('ffffffff…ffffff')).toBeInTheDocument();

    const timeElement = document.querySelector('time');
    expect(timeElement).not.toBeNull();
    expect(timeElement?.getAttribute('dateTime')).toBe(new Date(observedAt).toISOString());
  });
});
