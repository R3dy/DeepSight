/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from 'react';
import { io, Socket } from 'socket.io-client';
import { getAuthToken } from '../api';

type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

interface WebSocketContextValue {
  socket: Socket | null;
  status: ConnectionStatus;
  lastEvent: string | null;
  reconnectAttempt: number;
}

const SOCKET_URL = '/';
const RECONNECT_DELAYS = [1000, 2000, 4000, 8000, 16000, 30000];

const WebSocketContext = createContext<WebSocketContextValue | null>(null);

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [lastEvent, setLastEvent] = useState<string | null>(null);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);

  const connect = useCallback(() => {
    if (socket?.connected) return;

    setStatus('connecting');

    const token = getAuthToken();

    const newSocket = io(SOCKET_URL, {
      path: '/socket.io',
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: RECONNECT_DELAYS[0] || 1000,
      reconnectionDelayMax: 30000,
    });

    newSocket.on('connect', () => {
      setStatus('connected');
      setReconnectAttempt(0);
    });

    newSocket.on('connected', (data: { user?: string }) => {
      setLastEvent(`connected:${data.user || 'unknown'}`);
    });

    newSocket.on('host_stats', () => {
      setLastEvent('host_stats');
    });

    newSocket.on('new_alert', () => {
      setLastEvent('new_alert');
    });

    newSocket.on('incident_update', () => {
      setLastEvent('incident_update');
    });

    newSocket.on('disconnect', () => {
      setStatus('disconnected');
    });

    newSocket.on('connect_error', () => {
      setStatus('error');
    });

    newSocket.io.on('reconnect_attempt', () => {
      setReconnectAttempt(prev => prev + 1);
    });

    setSocket(newSocket);
  }, [socket]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- initial socket connection
    connect();
    return () => {
      setSocket(prev => {
        prev?.disconnect();
        return null;
      });
    };
    // Only run on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <WebSocketContext.Provider
      value={{
        socket,
        status,
        lastEvent,
        reconnectAttempt,
      }}
    >
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocket(): WebSocketContextValue {
  const ctx = useContext(WebSocketContext);
  if (!ctx) {
    throw new Error('useWebSocket must be used within WebSocketProvider');
  }
  return ctx;
}
