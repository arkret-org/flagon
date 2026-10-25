#!/usr/bin/env python3
"""Serve a built audit-console directory with SPA fallback, without rebuilding."""
import argparse
import http.server
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir',type=Path,required=True)
    parser.add_argument('--port',type=int,default=8080)
    args=parser.parse_args()
    root=args.dir.resolve()
    if not (root/'index.html').is_file():raise SystemExit(f'No browser bundle in {root}')
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self,*a,**kw):super().__init__(*a,directory=str(root),**kw)
        def do_GET(self):
            path=self.path.split('?')[0].lstrip('/')
            if path and '.' not in path.rsplit('/',1)[-1] and not (root/path).exists():self.path='/index.html'
            super().do_GET()
        def end_headers(self):
            self.send_header('Cache-Control','no-store')
            super().end_headers()
    print(f'Audit console at http://127.0.0.1:{args.port}',flush=True)
    http.server.ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()

if __name__=='__main__':main()
