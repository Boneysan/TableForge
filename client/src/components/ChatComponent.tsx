import React, { useState, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Send, MessageCircle } from 'lucide-react';
import { apiRequest } from '@/lib/queryClient';
import type { ChatMessage } from '@shared/schema';
import { format } from 'date-fns';

interface ChatComponentProps {
  roomId: string;
  websocket: WebSocket | null;
  currentUserId: string;
}

interface ChatMessageWithName extends ChatMessage {
  playerName: string;
}

export function ChatComponent({ roomId, websocket, currentUserId }: ChatComponentProps) {
  const [message, setMessage] = useState('');
  const [chatMessages, setChatMessages] = useState<ChatMessageWithName[]>([]);
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();

  // Fetch existing chat messages
  const { data: existingMessages } = useQuery<ChatMessageWithName[]>({
    queryKey: [`/api/rooms/${roomId}/chat`],
    enabled: !!roomId,
  });

  // Load existing messages when component mounts
  useEffect(() => {
    if (existingMessages) {
      setChatMessages(existingMessages);
    }
  }, [existingMessages]);

  // Listen for new chat messages via WebSocket
  useEffect(() => {
    if (!websocket) return;

    const handleMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'chat_message') {
          setChatMessages(prev => [...prev, data.payload]);
          // Scroll to bottom
          setTimeout(() => {
            if (scrollAreaRef.current) {
              scrollAreaRef.current.scrollTop = scrollAreaRef.current.scrollHeight;
            }
          }, 100);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    websocket.addEventListener('message', handleMessage);
    return () => websocket.removeEventListener('message', handleMessage);
  }, [websocket]);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollAreaRef.current) {
      scrollAreaRef.current.scrollTop = scrollAreaRef.current.scrollHeight;
    }
  }, [chatMessages]);

  // Send message mutation
  const sendMessageMutation = useMutation({
    mutationFn: async (messageText: string) => {
      const response = await fetch(`/api/rooms/${roomId}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: messageText,
          messageType: 'chat',
        }),
      });
      if (!response.ok) throw new Error('Failed to send message');
      return response.json();
    },
    onSuccess: () => {
      setMessage('');
      queryClient.invalidateQueries({ queryKey: [`/api/rooms/${roomId}/chat`] });
    },
    onError: (error) => {
      console.error('Error sending message:', error);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (message.trim() && !sendMessageMutation.isPending) {
      sendMessageMutation.mutate(message.trim());
    }
  };

  const formatMessageTime = (sentAt: string | Date | null) => {
    if (!sentAt) return '';
    return format(new Date(sentAt), 'HH:mm');
  };

  return (
    <Card className="h-full flex flex-col">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <MessageCircle className="w-4 h-4" />
          Chat
          <span className="text-xs text-gray-500">
            ({chatMessages.length} messages)
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex-1 flex flex-col p-3 gap-3">
        {/* Messages Area */}
        <ScrollArea className="flex-1 border rounded-md" ref={scrollAreaRef}>
          <div className="p-3 space-y-2" data-testid="chat-messages-container">
            {chatMessages.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-4">
                No messages yet. Start the conversation!
              </p>
            ) : (
              chatMessages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex flex-col gap-1 ${
                    msg.playerId === currentUserId ? 'items-end' : 'items-start'
                  }`}
                  data-testid={`chat-message-${msg.id}`}
                >
                  <div
                    className={`max-w-[80%] px-3 py-2 rounded-lg text-sm ${
                      msg.playerId === currentUserId
                        ? 'bg-blue-500 text-white'
                        : 'bg-gray-100 dark:bg-gray-800'
                    }`}
                  >
                    <div className="font-medium text-xs opacity-75 mb-1">
                      {msg.playerId === currentUserId ? 'You' : msg.playerName}
                    </div>
                    <div>{msg.message}</div>
                  </div>
                  <div className="text-xs text-gray-500">
                    {formatMessageTime(msg.sentAt)}
                  </div>
                </div>
              ))
            )}
          </div>
        </ScrollArea>

        {/* Message Input */}
        <form onSubmit={handleSubmit} className="flex gap-2">
          <Input
            type="text"
            placeholder="Type a message..."
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={sendMessageMutation.isPending}
            className="flex-1"
            data-testid="chat-input"
          />
          <Button
            type="submit"
            disabled={!message.trim() || sendMessageMutation.isPending}
            size="sm"
            data-testid="chat-send-button"
          >
            <Send className="w-4 h-4" />
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
