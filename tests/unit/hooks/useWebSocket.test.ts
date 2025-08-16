// tests/unit/hooks/useWebSocket.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { WebSocketMessage } from '@shared/schema';

// Mock WebSocket for testing
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  public readyState = MockWebSocket.CONNECTING;
  public onopen: ((event: Event) => void) | null = null;
  public onclose: ((event: CloseEvent) => void) | null = null;
  public onmessage: ((event: MessageEvent) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;

  constructor(public url: string) {
    // Simulate async connection
    setTimeout(() => {
      if (url.includes('invalid')) {
        this.readyState = MockWebSocket.CLOSED;
        this.onerror?.(new Event('error'));
        this.onclose?.(new CloseEvent('close', { code: 1006, reason: 'Connection failed' }));
      } else {
        this.readyState = MockWebSocket.OPEN;
        this.onopen?.(new Event('open'));
      }
    }, 10);
  }

  send(data: string) {
    if (this.readyState === MockWebSocket.OPEN) {
      // Echo back the message for testing
      setTimeout(() => {
        this.onmessage?.(new MessageEvent('message', { data }));
      }, 5);
    }
  }

  close(code?: number, reason?: string) {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.(new CloseEvent('close', { code: code || 1000, reason: reason || 'Normal closure' }));
  }
}

// Mock the global WebSocket
(globalThis as any).WebSocket = MockWebSocket;

// Mock window.location for URL construction
Object.defineProperty(window, 'location', {
  value: {
    protocol: 'http:',
    host: 'localhost:3000'
  },
  writable: true
});

describe('useWebSocket', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllTimers();
  });

  it('should connect to WebSocket server', async () => {
    const { result } = renderHook(() => useWebSocket());

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });
    
    expect(result.current.connected).toBe(true);
    expect(result.current.error).toBeNull();
  });

  it('should handle incoming messages', async () => {
    const onMessage = vi.fn();
    const { result } = renderHook(() => useWebSocket({ onMessage }));

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    const testMessage: WebSocketMessage = { 
      type: 'test', 
      payload: { message: 'hello' },
      timestamp: Date.now()
    };
    
    act(() => {
      // Simulate receiving a message
      const event = new MessageEvent('message', { 
        data: JSON.stringify(testMessage) 
      });
      (result.current.websocket as any)?.onmessage?.(event);
    });

    expect(onMessage).toHaveBeenCalledWith(testMessage);
  });

  it('should send messages', async () => {
    const { result } = renderHook(() => useWebSocket());

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    const message: WebSocketMessage = { 
      type: 'asset_moved', 
      payload: { 
        assetId: 'asset1',
        positionX: 100, 
        positionY: 200 
      }
    };
    
    const sendSpy = vi.spyOn(result.current.websocket as any, 'send');
    
    act(() => {
      result.current.sendMessage(message);
    });

    expect(sendSpy).toHaveBeenCalledWith(JSON.stringify(message));
  });

  it('should handle connection errors', async () => {
    // Mock WebSocket to fail connection
    const OriginalWebSocket = (globalThis as any).WebSocket;
    (globalThis as any).WebSocket = class extends MockWebSocket {
      constructor(url: string) {
        super(url);
        setTimeout(() => {
          this.readyState = MockWebSocket.CLOSED;
          this.onerror?.(new Event('error'));
          this.onclose?.(new CloseEvent('close', { code: 1006, reason: 'Connection failed' }));
        }, 10);
      }
    };

    const { result } = renderHook(() => useWebSocket());

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(false);
    expect(result.current.error).toBeTruthy();

    // Restore original WebSocket
    (globalThis as any).WebSocket = OriginalWebSocket;
  });

  it('should reconnect on connection loss', async () => {
    const onConnect = vi.fn();
    const onDisconnect = vi.fn();
    
    const { result } = renderHook(() => useWebSocket({ 
      onConnect,
      onDisconnect,
      reconnectAttempts: 3,
      reconnectInterval: 100 
    }));

    // Wait for initial connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);
    expect(onConnect).toHaveBeenCalled();

    // Simulate connection loss
    act(() => {
      (result.current.websocket as any)?.onclose?.(
        new CloseEvent('close', { code: 1006, reason: 'Connection lost' })
      );
    });

    expect(result.current.connected).toBe(false);
    expect(onDisconnect).toHaveBeenCalled();

    // Wait for reconnection attempt
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 150));
    });

    expect(result.current.connected).toBe(true);
  });

  it('should handle multiple message types', async () => {
    const onMessage = vi.fn();
    const { result } = renderHook(() => useWebSocket({ onMessage }));

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    const messages: WebSocketMessage[] = [
      { 
        type: 'player_joined', 
        payload: { playerId: 'player1', playerName: 'Test Player' },
        roomId: 'test-room'
      },
      { 
        type: 'asset_moved', 
        payload: { 
          assetId: 'asset1', 
          positionX: 100, 
          positionY: 200 
        },
        roomId: 'test-room'
      },
      { 
        type: 'chat_message', 
        payload: { 
          message: 'Hello world', 
          playerName: 'Test Player' 
        },
        roomId: 'test-room'
      }
    ];

    for (const message of messages) {
      act(() => {
        const event = new MessageEvent('message', { 
          data: JSON.stringify(message) 
        });
        (result.current.websocket as any)?.onmessage?.(event);
      });
    }

    expect(onMessage).toHaveBeenCalledTimes(3);
    expect(onMessage).toHaveBeenNthCalledWith(1, messages[0]);
    expect(onMessage).toHaveBeenNthCalledWith(2, messages[1]);
    expect(onMessage).toHaveBeenNthCalledWith(3, messages[2]);
  });

  it('should handle malformed messages gracefully', async () => {
    const onMessage = vi.fn();
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    
    const { result } = renderHook(() => useWebSocket({ onMessage }));

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    // Send malformed JSON
    act(() => {
      const event = new MessageEvent('message', { 
        data: 'invalid json {' 
      });
      (result.current.websocket as any)?.onmessage?.(event);
    });

    // Should not crash and should log error
    expect(result.current.connected).toBe(true);
    expect(consoleSpy).toHaveBeenCalledWith('Failed to parse WebSocket message:', expect.any(Error));
    expect(onMessage).not.toHaveBeenCalled();

    consoleSpy.mockRestore();
  });

  it('should cleanup on unmount', async () => {
    const { result, unmount } = renderHook(() => useWebSocket());

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);

    const closeSpy = vi.spyOn(result.current.websocket as any, 'close');

    unmount();

    expect(closeSpy).toHaveBeenCalledWith(1000, 'Manual disconnect');
  });

  it('should handle manual disconnect', async () => {
    const { result } = renderHook(() => useWebSocket());

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);

    const closeSpy = vi.spyOn(result.current.websocket as any, 'close');

    act(() => {
      result.current.disconnect();
    });

    expect(closeSpy).toHaveBeenCalledWith(1000, 'Manual disconnect');
  });

  it('should handle manual reconnect', async () => {
    const { result } = renderHook(() => useWebSocket());

    // Wait for initial connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    // Disconnect
    act(() => {
      result.current.disconnect();
    });

    // Manually reconnect
    act(() => {
      result.current.connect();
    });

    // Wait for reconnection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);
  });

  it('should warn when sending message while disconnected', async () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    
    const { result } = renderHook(() => useWebSocket());

    const message: WebSocketMessage = { 
      type: 'test', 
      payload: {}
    };

    // Send message before connection
    act(() => {
      result.current.sendMessage(message);
    });

    expect(consoleSpy).toHaveBeenCalledWith(
      'WebSocket is not connected. Cannot send message:', 
      message
    );

    consoleSpy.mockRestore();
  });

  it('should stop reconnecting after max attempts', async () => {
    const onDisconnect = vi.fn();
    
    // Mock WebSocket to always fail connection without ever opening
    (globalThis as any).WebSocket = class {
      public readyState = 3; // CLOSED
      public onopen: ((event: Event) => void) | null = null;
      public onclose: ((event: CloseEvent) => void) | null = null;
      public onmessage: ((event: MessageEvent) => void) | null = null;
      public onerror: ((event: Event) => void) | null = null;

      constructor(public url: string) {
        // Immediately fail without ever opening
        setTimeout(() => {
          this.onclose?.(new CloseEvent('close', { code: 1006, reason: 'Connection failed' }));
        }, 10);
      }

      send() {}
      close() {}
    };

    const { result } = renderHook(() => useWebSocket({ 
      onDisconnect,
      reconnectAttempts: 2,
      reconnectInterval: 50
    }));

    // Wait for initial connection attempt and failure
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 50));
    });

    expect(result.current.connected).toBe(false);

    // Wait for all reconnection attempts to complete
    // 2 attempts * 50ms interval + buffer time
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 250));
    });

    // After max attempts, should have error message
    expect(result.current.error).toBe('Failed to reconnect after multiple attempts');
    expect(onDisconnect).toHaveBeenCalled();
  });
});
