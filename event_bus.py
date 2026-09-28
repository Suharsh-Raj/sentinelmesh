import asyncio
from collections import defaultdict

class EventBus:
    def __init__(self):
        self.subscribers = set()
        self.handlers = []

    def add_handler(self, handler):
        if handler not in self.handlers: self.handlers.append(handler)

    def subscribe(self):
        queue = asyncio.Queue(maxsize=100)
        self.subscribers.add(queue)
        return queue

    def unsubscribe(self, queue): self.subscribers.discard(queue)

    async def publish(self, event):
        for handler in self.handlers:
            result = handler(event)
            if hasattr(result, "__await__"): await result
        for queue in list(self.subscribers):
            if queue.full():
                try: queue.get_nowait()
                except asyncio.QueueEmpty: pass
            try: queue.put_nowait(event)
            except asyncio.QueueFull: pass

bus = EventBus()
