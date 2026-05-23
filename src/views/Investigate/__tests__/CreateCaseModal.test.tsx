import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { CreateCaseModal } from '../CreateCaseModal';

// Mock the cases API
vi.mock('../../../api/cases', () => ({
  createCase: vi.fn(),
}));

import { createCase } from '../../../api/cases';

function renderModal(open = true) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const onClose = vi.fn();

  const utils = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <CreateCaseModal open={open} onClose={onClose} />
      </MemoryRouter>
    </QueryClientProvider>
  );

  return { ...utils, onClose };
}

describe('CreateCaseModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('renders nothing when closed', () => {
    const { container } = renderModal(false);
    expect(container.innerHTML).toBe('');
  });

  it('renders the create form when open', () => {
    renderModal(true);
    expect(screen.getByText('Create New Case')).toBeTruthy();
    expect(screen.getByLabelText(/Title/)).toBeTruthy();
    expect(screen.getByLabelText(/Description/)).toBeTruthy();
    expect(screen.getByLabelText(/Severity/)).toBeTruthy();
    expect(screen.getByLabelText(/Priority/)).toBeTruthy();
    // Use queryAllByText since the header "Create New Case" contains "Create"
    const buttons = screen.getAllByRole('button', { name: 'Create Case' });
    expect(buttons.length).toBeGreaterThan(0);
  });

  it('closes when Cancel is clicked', async () => {
    const { onClose } = renderModal(true);
    const cancelButtons = screen.getAllByRole('button', { name: 'Cancel' });
    await userEvent.click(cancelButtons[0]);
    expect(onClose).toHaveBeenCalled();
  });

  it('closes when backdrop is clicked', async () => {
    const { onClose } = renderModal(true);
    // The backdrop is the first element with class bg-black/60
    const backdrops = document.querySelectorAll('.fixed.inset-0.z-40');
    expect(backdrops.length).toBeGreaterThan(0);
    await userEvent.click(backdrops[backdrops.length - 1] as HTMLElement);
    expect(onClose).toHaveBeenCalled();
  });

  it('shows validation error for empty title', async () => {
    renderModal(true);
    const createButtons = screen.getAllByRole('button', { name: 'Create Case' });
    // Get the last rendered button (most recent modal)
    await userEvent.click(createButtons[createButtons.length - 1]);
    expect(screen.getByText('Title is required')).toBeTruthy();
  });

  it('submits form with correct data', async () => {
    const mockCreate = vi.mocked(createCase).mockResolvedValue({
      ok: true,
      data: {
        id: 1,
        title: 'Test Case',
        description: 'Test',
        severity: 'high',
        status: 'new',
        priority: 'high',
        assignee_id: null,
        source_host: '',
        mitre_technique: '',
        tags: ['test'],
        created_at: '2026-05-23T00:00:00Z',
        updated_at: '2026-05-23T00:00:00Z',
        resolved_at: null,
        resolution: '',
        resolved_note: '',
        sla_deadline: null,
        sla_breached: false,
        sla_remaining_seconds: 0,
        alert_count: 0,
      },
    } as never);

    renderModal(true);

    const titleInput = screen.getByLabelText(/Title/);
    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, 'Test Case');
    await userEvent.type(screen.getByLabelText(/Description/), 'Test description');
    await userEvent.selectOptions(screen.getByLabelText(/Severity/), 'high');
    await userEvent.selectOptions(screen.getByLabelText(/Priority/), 'high');
    await userEvent.type(screen.getByLabelText(/Tags/), 'test');

    const createButtons = screen.getAllByRole('button', { name: 'Create Case' });
    await userEvent.click(createButtons[createButtons.length - 1]);

    await waitFor(() => {
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Test Case',
          description: 'Test description',
          severity: 'high',
          priority: 'high',
          tags: ['test'],
        })
      );
    });
  });

  it('disables submit button during submission', async () => {
    // Simulate pending state by never resolving
    vi.mocked(createCase).mockImplementation(() => new Promise(() => {}));

    renderModal(true);

    await userEvent.type(screen.getByLabelText(/Title/), 'Test Case');
    const createButtons = screen.getAllByRole('button', { name: 'Create Case' });
    await userEvent.click(createButtons[createButtons.length - 1]);

    await waitFor(() => {
      expect(screen.getByText('Creating...')).toBeTruthy();
    });
  });
});
