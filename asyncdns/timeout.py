import asyncio

class Timeout(object):
    def __init__(self, timeout, callback):
        loop = asyncio.get_event_loop()
        loop.call_later(timeout, self.fire)
        self.callback = callback
        self.cancelled = False

    def fire(self):
        if self.cancelled:
            return
        self.callback()

    def cancel(self):
        self.cancelled = True
        self.callback = None

