import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ErrorBoundary } from '../ui/ErrorBoundary';

function ThrowError(): never {
  throw new Error('Test error');
}

// Suppress console.error for expected errors
const originalError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === 'string' && args[0].includes('Test error')) return;
  originalError.call(console, ...args);
};

describe('ErrorBoundary', () => {
  it('renders children when no error', () => {
    render(
      <ErrorBoundary>
        <div>Hello World</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('Hello World')).toBeTruthy();
  });

  it('renders error UI when child throws', () => {
    render(
      <ErrorBoundary>
        <ThrowError />
      </ErrorBoundary>
    );
    expect(screen.getByText('Something went wrong')).toBeTruthy();
    expect(screen.getByText('Test error')).toBeTruthy();
  });

  it('renders custom fallback when provided', () => {
    render(
      <ErrorBoundary fallback={<div>Custom Error</div>}>
        <ThrowError />
      </ErrorBoundary>
    );
    expect(screen.getByText('Custom Error')).toBeTruthy();
  });

  it('recovers after clicking Try Again', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError />
      </ErrorBoundary>
    );
    expect(screen.getByText('Something went wrong')).toBeTruthy();

    // Click try again
    screen.getByText('Try Again').click();

    // Re-render with valid children
    rerender(
      <ErrorBoundary>
        <div>Recovered</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('Recovered')).toBeTruthy();
  });
});
