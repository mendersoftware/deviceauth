#!/usr/bin/python3
# Copyright 2016 Mender Software AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
import os
import threading
import logging
from contextlib import contextmanager
from concurrent import futures

import tornado.web
import tornado.ioloop

class MockRequestHandler(tornado.web.RequestHandler):
    log = logging.getLogger('MockRequestHandler')

    def initialize(self, handlers=[]):
        self.handlers = handlers

    def post(self, *args, **kwargs):
        self._run_handlers(*args, **kwargs)

    def get(self, *args, **kwargs):
        self._run_handlers(*args, **kwargs)

    def delete(self, *args, **kwargs):
        self._run_handlers(*args, **kwargs)

    def put(self, *args, **kwargs):
        self._run_handlers(*args, **kwargs)

    def patch(self, *args, **kwargs):
        self._run_handlers(*args, **kwargs)

    def _run_handlers(self, *args, **kwargs):
        for method, uri, callback in self.handlers:
            # find and execute matching handler
            if method == self.request.method and \
               uri == self.request.uri and callback:

                status, headers, body = callback()
                # set status
                self.set_status(status)

                # set headers
                for hdr, val in headers.items():
                    self.add_header(hdr, val)

                # push body
                if body:
                    self.write(body)

                self.finish()

                break
        else:
            self.log.error('no handler for request %s', self.request)
            raise tornado.web.HTTPError(405)


class MockServer:
    log = logging.getLogger('MockServer')

    def __init__(self, listen=('0.0.0.0', 9999), handlers=[]):
        self.app = tornado.web.Application([
            (r"/.*", MockRequestHandler, dict(handlers=handlers)),
        ])

        self.listen = listen
        self.thread = None
        self.loop = None

    def _start_loop_thread(self, sync):
        """Thread.run() callback that starts the loop and signals that it has started
        by setting `sync` to True"""
        self.log.info('starting test tenantadm server in thread')

        host, port = self.listen[0], self.listen[1]

        self.loop = tornado.ioloop.IOLoop(make_current=True)
        self.log.info('listen on %s:%s', host, port)
        self.app.listen(port, address=host)

        self.log.info('starting loop')

        # sync with our caller
        self.loop.add_callback(lambda: sync.set_result(True))

        self.loop.start()

    def _stop_loop_thread(self):
        """In IO loop callback to stop the loop"""
        self.log.info('stopping test tenantadm server')
        self.loop.stop()

    def run_thread_and_sync(self):
        """Start the server in a separate thread and wait for notification that it has
        successfuly started"""

        # create future so that we can sync with the IO loop running inside the
        # thread we started
        sync = futures.Future()

        self.thread = threading.Thread(target=self._start_loop_thread, args=(sync,))
        self.thread.start()

        # wait for the loop to be stated
        futures.wait([sync])

        self.log.info('tenantadm thread started')

        return self

    def stop_thread_and_wait(self):
        """Stop the server running in separate thread and wait its IO loop to finish"""

        self.log.info('tenantadm stop..')
        if not self.thread:
            return

        # run stop in loop context
        self.loop.add_callback(self._stop_loop_thread)
        # wait for thread
        self.thread.join()

        self.thread = None

        # cleanup the loop & close all file descriptors (NOTE: this will make
        # our server stop listening for connections)
        self.loop.close(all_fds=True)
        self.loop = None

    def wait(self):
        if not self.thread:
            return

        self.thread.join()


@contextmanager
def run_fake(listen_addr, handlers=[]):
    """run_fake acts as a context manager and can be used to create a tenantadm
    server listening on `listen_addr`"""
    sp = listen_addr.split(':')
    host, port = sp[0], int(sp[1]) if len(sp) > 1 else 9999

    try:
        mock_server = MockServer((host, port), handlers=handlers)
        yield mock_server.run_thread_and_sync()
    finally:
        mock_server.stop_thread_and_wait()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    handlers = [
        ('POST', '/api/internal/v1/tenantadm/tenants/verify',
         lambda: (200, {'Foo': 'bar'}, '')),
        ('POST', '/api/internal/v1/tenantadm/tenants/verify/bad',
         lambda: (401, {}, '')),
        ('POST', '/api/internal/v1/tenantadm/tenants/login',
         lambda: (200, {}, 'token-token')),
    ]
    with run_fake('0.0.0.0:9999', handlers=handlers) as server:
        server.wait()
