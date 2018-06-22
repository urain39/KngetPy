#!/usr/bin/env python3
# coding: utf-8

import os
import re
import sys
import json
import time
import random
import requests
from hashlib import sha1
from inifile import IniFile
from inifile import IniException

_NO_ERROR = 0
_CONFIG_ERROR = 1
_USAGE_ERROR = 2
_CONNECT_ERROR = 3
_DOWNLOAD_ERROR = 4

_USAGE = '''\
Usage: {0} <tags> <[begin]<end>>
'''.format(sys.argv[0])

_CONFIG_TIPS = '''\
; KngetPy Project.
; File auto-generated by {0}
;
; Edit the base_url in the custom section
; to download different kind of images on site.
;
; Project links:
;   https://github.com/urain39/KngetPy
;   https://github.com/urain39/IniFilePy
;
'''.format(sys.argv[0])

_DEFAUL_CONFIG = {
    'custom': {
        'base_url': 'https://capi.sankakucomplex.com',
        'page_limit': 10,
        'user_agent': 'SCChannelApp/3.0 (Android; black)',
        'load_time_fake': '3-5'
    },
    'download': {
        'timeout': 10,
        'maxsize': 10,
        'bufsize': 1048576,
        'retry_wait': 8,
        'retry_count': 3
    },
    'account': {
        'username': 'knget',
        'password': 'knget.py'
    }
}

class KngetError():
    pass


class Knget():
    def __init__(self, config):
        self._tags = []
        self._curdir = os.getcwd()
        self._custom = config.get_section('custom')
        self._config = config.get_section('download')
        self._account = config.get_section('account')
        self._session = requests.Session()
        self._login_data = dict()
        self._task_pool = dict()
        self._meta_infos = list()
        self._session.headers = {
                'Accept': '*/*',
                'Connection': 'Keep-Alive',
                'User-Agent': self._custom.get('user_agent'),
        }
        self._session.cookies = requests.cookies.cookielib.LWPCookieJar('cookies.txt')

        if os.path.exists('cookies.txt'):
            self._msg('Loading cookies.')
            self._session.cookies.load(ignore_discard=True)

    def _load_faker(self):
        load_time_fake = [
            int(i) for i in (
                self._custom.get('load_time_fake') or '1-3'
            ).split('-')[:2]
        ]

        load_time = random.randint(*load_time_fake) + random.random()

        self._msg2("Load time: %0.2f" % load_time)
        time.sleep(load_time)

    def _login(self, username, password):
        for cookie_name in [cookie.name.lower() for cookie in self._session.cookies]:
            if 'sankaku' in cookie_name:
                self._msg('Logined, skip login.')
                return

        appkey = sha1(
            'sankakuapp_{0}_Z5NE9YASej'.format(
                username
            ).encode()
        ).hexdigest()

        password_hash = sha1(
            'choujin-steiner--{0}--'.format(
                password
            ).encode()
        ).hexdigest()

        self._login_data.update(
            {
                'login': username,
                'password_hash': password_hash,
                'appkey': appkey
            }
        )

        response = self._session.post(
            '{base_url}/user/authenticate.json'.format(
                base_url=self._custom.get('base_url')
            ),
            data={
                'user[name]': username,
                'user[password]': password,
                'appkey': appkey
            }
        )

        if not (response.ok and response.json().get('success')):
            raise KngetError('Cannot login!')

    def _msg(self, msg):
        sys.stderr.write('=> {0}\n'.format(msg))

    def _msg2(self, msg):
        sys.stderr.write('    => {0}\n'.format(msg))

    def _chdir(self, tags):
            save_dir = 'kn-' + '-'.join(
                tags.split()
            )

            if not os.path.exists(save_dir):
                if os.path.isfile(save_dir):
                    os.remove(save_dir)
                os.mkdir(save_dir)
            os.chdir(save_dir)

    def _check_url(self, url):
        protocol = re.match(r'((?:ht|f)tps?:).*', url)

        if protocol is None:
            # 从base_url获取协议头
            base_url = self._custom.get('base_url')
            return re.match(r'((?:ht|f)tps?:).*', base_url).group(1) + url

        return url

    def _download(self, job):
        url =  job['file_url']
        file_size = job['file_size']
        file_name = '{post_id}.{file_ext}'.format(
            post_id=job['id'],
            # 使用较保守的方法获取扩展名
            file_ext=job['file_url'].split('.')[-1]
        )

        file_name = file_name.split('?')[0]

        response = self._session.get(
            url=self._check_url(url),
            stream=True,
            timeout=self._config.get('timeout') or 10,
            params=self._login_data
        )

        self._load_faker()
        if not os.path.exists(file_name) or os.path.getsize(file_name) != file_size:
            with open(file_name, 'wb') as fp:
                bufsize = self._config.get('bufsize') or (1<<20)

                for data in response.iter_content(chunk_size=bufsize):
                    fp.write(data)

    def _cleanup(self):
        if not len(self._meta_infos) < 1:
            with open('meta_data.json', 'w') as fp:
                json.dump(self._meta_infos, fp)

        os.chdir(self._curdir)
        for _dir in os.listdir(self._curdir):
            if os.path.isdir(_dir) and len(os.listdir(_dir)) < 1:
                os.rmdir(_dir)
                self._msg2('save_dir {0} is empty, removed.'.format(_dir))

    def _filter(self):
        post_rating = self._custom.get('post_rating')
        post_min_score = self._custom.get('post_min_score')
        post_tags_blacklist = self._custom.get('post_tags_blacklist')

        if post_rating != r'' and post_rating != None:
            self._task_pool = [
                task
                for task in self._task_pool
                    if task.get('rating') in post_rating.split()
            ]

        if post_min_score != r'' and post_min_score != None:
            self._task_pool = [
                task
                for task in self._task_pool
                    if (task.get('score') or task.get('total_score' or 0)) >= post_min_score
            ]

        if post_tags_blacklist != r'' and post_tags_blacklist != None:
            self._task_pool = [
                task
                for task in self._task_pool
                    if all([tag not in post_tags_blacklist.split() for tag in task['tags'].split()])
            ]

    def work(self):
        self._filter()

        jobs_count = len(self._task_pool)
        retry_count = self._config.get('retry_count')
        retry_wait = self._config.get('retry_wait')

        cur_jobs_count = 0
        cur_retry_count = 0

        self._meta_infos.extend(self._task_pool)

        for job in self._task_pool:
            file_size = job.get('file_size')

            if (file_size or 0) < self._config.get('maxsize') * (1<<20):
                cur_jobs_count += 1
                cur_retry_count = 0

                while True:
                    try:
                        self._msg2('Process: %4d / %-4d' % (cur_jobs_count, jobs_count))

                        self._download(job)
                        break
                    except requests.exceptions.RequestException as e:
                        if cur_retry_count < retry_count:
                            self._msg2('Error: {0}'.format(e))
                            self._msg2('wait {0}s...'.format(retry_wait))
                            time.sleep(retry_wait)
                            cur_retry_count += 1
                            continue
                        else:
                            self._cleanup()
                            sys.exit(_DOWNLOAD_ERROR)

    def run(self, tags, begin, end):
        self._chdir(tags)
        self._tags = tags
        self._login(
            username=str(self._account.get('username')),
            password=str(self._account.get('password'))
        )

        for page in range(begin, end + 1):
            self._load_faker()
            self._msg('[Page = {0} | tags = {1}]'.format(page, tags))

            payload = {
                    'page': page,
                    'tags': tags,
                    'limit': self._custom.get('page_limit')
            }
            payload.update(self._login_data)

            response = self._session.get(
                self._custom.get('base_url') + '/post/index.json',
                timeout=self._config.get('timeout'),
                params=payload
            )

            self._task_pool = response.json()

            if len(self._task_pool) < 1:
                break
            elif len(self._task_pool) < self._custom.get('page_limit'):
                self.work()
                break
            else:
                self.work()
        self._cleanup()
        self._session.cookies.save(ignore_discard=True)


def usage(status=None):
    print(_USAGE)

    if status is None:
        return
    else:
        sys.exit(status)

def main(argv):
    if os.path.exists('config.ini'):
        try:
            config = IniFile('config.ini')
        except IniException as e:
            print('{0}\n'.format(e))
            print('Possible cannot read?')
            sys.exit(_CONFIG_ERROR)
    else:
        with open('config.ini', 'w') as fp:
            config = IniFile()
            config.reset(_DEFAUL_CONFIG)
            fp.write(_CONFIG_TIPS + '\n')
            config.dump(fp)

    knget = Knget(config)

    if len(argv) < 3:
        return usage(_USAGE_ERROR)
    elif len(argv) == 3:
        knget.run(argv[1], 1 ,int(argv[2]))
    elif len(argv) == 4:
        knget.run(argv[1], int(argv[2]), int(argv[3]))
    else:
        return usage(_USAGE_ERROR)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.exit(_NO_ERROR)
