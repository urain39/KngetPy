#!/usr/bin/env python
# coding: utf-8

import os
import re
import sys
import time
import random
import json
import shlex

from hashlib import sha1
from requests import Session
from requests.cookies import cookielib
from requests.exceptions import RequestException
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory


__all__ = [
    'main',
    'Knget',
    'KngetShell',
    'KngetError',
    'KngetCommand'
]

_NO_ERROR = 0
_CONFIG_ERROR = 1
_USAGE_ERROR = 2
_CONNECT_ERROR = 3
_DOWNLOAD_ERROR = 4

_USAGE = '''\
Usage: {0} <tags> <[begin]<end>>
'''.format(sys.argv[0])

# Ensure _PROMPT_STR is unicode
_PROMPT_STR = u'KGSH> '
_DEFAULT_CONFIG = {
    'custom': {
        'base_url': 'https://konachan.net',
        'page_limit': 10,
        'user_agent': 'Mozilla/5.0 (Linux; LittleKaiju)',
        'load_time_fake': '1-2',
        'post_rating': 's',  # at least one of 'e q s', split by space.
        'post_min_score': 0,
        'post_tags_blacklist': 'video mp4 webm',
        'save_cookies': False
    },
    'download': {
        'timeout': 30,
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


class KngetError(Exception):
    """KngetPy BaseException.
    """

    def __init__(self, msg, reason=None):
        self._reason = reason
        super(KngetError, self).__init__(msg)


class Knget(object):
    def load_config(self, config_path=None):
        config = {}
        config_path = config_path or (self._homedir + '/knget.json')

        if os.path.exists(config_path):
            with open(config_path) as fp:
                config = json.load(fp)
        else:
            with open(config_path, 'w') as fp:
                config = _DEFAULT_CONFIG
                json.dump(config, fp, indent=2)

        self._custom = config.get('custom')
        self._account = config.get('account')
        self._config = config.get('download')

    def _debug_info(self):
        """Show a list of recently variables info.
        """
        self._msg('DEBUG')
        self._msg2('WorkDir: {0}'.format(self._curdir))
        self._msg2('Logined: {0}'.format(self._login_data))
        self._msg2('Cookies: {0}'.format(self._session.cookies))
        self._msg2('Headers: {0}'.format(self._session.headers))
        self._msg2('Configs: {0}'.format(self._config))
        self._msg2('Customs: {0}'.format(self._custom))

    def __init__(self):
        self._ordered_id = 0
        self._curdir = os.getcwd()
        self._homedir = os.getenv('HOME', '.')
        self._custom = {}
        self._config = {}
        self._account = {}
        self._session = Session()
        self._logined = False
        self._login_data = {}
        self._task_pool = {}
        self._meta_infos = []

        self.load_config()
        self._session.headers = {
            'Accept': '*/*',
            'Connection': 'Keep-Alive',
            'User-Agent': self._custom.get('user_agent'),
        }

        self._session.cookies = cookielib.LWPCookieJar(self._homedir + '/cookies.txt')

        if os.path.exists(self._homedir + '/cookies.txt'):
            self._msg('Loading cookies.')
            self._session.cookies.load()

    def _loader_fake(self):
        load_time_fake = [
            int(i) for i in (
                self._custom.get('load_time_fake') or '1-3'
            ).split('-')[:2]
        ]

        load_time = random.randint(*load_time_fake) + random.random()

        self._msg2("Load time: %0.2f" % load_time)
        time.sleep(load_time)

    def _login(self, username, password):
        if self._logined:
            return self._msg2("Logined, skip login.")

        password_hash = sha1(
            'choujin-steiner--{0}--'.format(password).encode()
        ).hexdigest()

        self._login_data.update(
            {
                'login': username,
                'password_hash': password_hash
            }
        )

        response = self._session.post(
            '{base_url}/user/authenticate.json'.format(
                base_url=self._custom.get('base_url')
            ),
            data={
                'user[name]': username,
                'user[password]': password
            }
        )

        if not (response.ok and response.json().get('success')):
            raise KngetError('Cannot login!',
                             reason=response.json().get('reason'))

        self._logined = True

    def _msg(self, msg):
        sys.stderr.write('=> {0}\n'.format(msg))

    def _msg2(self, msg):
        sys.stderr.write('    => {0}\n'.format(msg))

    def _chdir(self, tags):
            save_dir = 'kn-' + '-'.join(tags.split())

            # FIXME: Windows filename cannot with '< > / \ | : " * ?'

            # XXX: As far as i know
            save_dir = save_dir.replace(':', '.')
            save_dir = save_dir.replace('*', '+')
            save_dir = save_dir.replace('?', '!')
            save_dir = save_dir.replace('<', '(')
            save_dir = save_dir.replace('>', ')')

            if not os.path.exists(save_dir):
                if os.path.isfile(save_dir):
                    os.remove(save_dir)
                os.mkdir(save_dir)
            os.chdir(save_dir)

    def _check_url(self, url):
        protocol = re.match(r'((?:ht|f)tps?:).*', url)

        if protocol is None:
            # Get protocol from base_url
            base_url = self._custom.get('base_url')
            return re.match(r'((?:ht|f)tps?:).*', base_url).group(1) + url

        return url

    def _download(self, job):
        url = job['file_url']
        file_size = job['file_size']
        file_name = '{post_id}.{file_ext}'.format(
            post_id=job['id'],
            # XXX: Some sites not have file_ext attribute!
            file_ext=job['file_url'].split('.')[-1]
        )

        file_name = file_name.split('?')[0]
        file_name = '{0:06d}_{1:6s}'.format(self._ordered_id, file_name)

        response = self._session.get(
            url=self._check_url(url),
            stream=True,
            timeout=self._config.get('timeout') or 10,
            params=self._login_data
        )

        self._loader_fake()
        if (not os.path.exists(file_name) or
                os.path.getsize(file_name) != file_size):
            with open(file_name, 'wb') as fp:
                bufsize = self._config.get('bufsize') or (1 << 20)

                for data in response.iter_content(chunk_size=bufsize):
                    fp.write(data)

    def _cleanup(self):
        if not len(self._meta_infos) < 1:
            with open('meta_data.json', 'w') as fp:
                json.dump(self._meta_infos, fp)

        os.chdir(self._curdir)
        for _dir in os.listdir(self._curdir):
            if not os.path.isdir(_dir):
                continue  # Skip file.

            if len(os.listdir(_dir)) < 1:
                os.rmdir(_dir)
                self._msg2('save_dir {0} is empty, removed.'.format(_dir))
                continue  # Next directory

            if len(os.listdir(_dir)) == 1 and os.path.exists(_dir + '/meta_data.json'):
                os.remove(_dir + '/meta_data.json')
                os.rmdir(_dir)
                self._msg2('save_dir {0} not found images, removed.'.format(_dir))

    def _filter(self):
        post_rating = self._custom.get('post_rating')
        post_min_score = self._custom.get('post_min_score')
        post_tags_blacklist = self._custom.get('post_tags_blacklist')

        if post_rating != r'' and post_rating is not None:
            self._task_pool = [
                task for task in self._task_pool
                    if task.get('rating') in post_rating.split()
            ]

        if post_min_score != r'' and post_min_score is not None:
            self._task_pool = [
                task for task in self._task_pool
                    if int(task.get('score') or
                        task.get('total_score') or 0) >= post_min_score
            ]

        if post_tags_blacklist != r'' and post_tags_blacklist is not None:
            if 'sankaku' in self._custom.get('base_url'):
                # XXX: Handle sankaku site's tags
                self._task_pool = [
                    task for task in self._task_pool
                        if all( tag['name'] not in post_tags_blacklist.split()
                                for tag in task['tags'])
                ]
            else:
                self._task_pool = [
                    task for task in self._task_pool
                        if all( tag not in post_tags_blacklist.split()
                                for tag in task['tags'].split())
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

            if (file_size or 0) < self._config.get('maxsize') * (1 << 20):
                cur_jobs_count += 1
                cur_retry_count = 0

                while True:
                    try:
                        self._msg2('Process: %4d / %-4d' %
                                   (cur_jobs_count, jobs_count))

                        self._download(job)
                        self._ordered_id += 1  # Next
                        break
                    except RequestException as e:
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
        self._ordered_id = 0

        for page in range(begin, end + 1):
            self._loader_fake()
            self._msg('[Page = {0} | tags = {1}]'.format(page, tags))

            payload = {
                    'page': page,
                    'tags': tags,
                    'limit': self._custom.get('page_limit')
            }

            # Add credential
            payload.update(self._login_data)

            # Get the index data.
            try:
                response = self._session.get(
                    self._custom.get('base_url') + '/post/index.json',
                    timeout=self._config.get('timeout'),
                    params=payload)

                self._task_pool = response.json()

                if not isinstance(self._task_pool, list):
                    raise KngetError('response is not a list!',
                                     reason="{0}".format(self._task_pool))
            except (RequestException, ValueError) as e:
                raise KngetError('Cannot decode JSON or Request Error!',
                                 reason='{0}'.format(e))

            # Do the job from index data.
            if len(self._task_pool) < 1:
                break
            elif len(self._task_pool) < self._custom.get('page_limit'):
                self.work()
                break
            else:
                self.work()
        self._cleanup()

        if self._custom.get('save_cookies'):
            self._session.cookies.save()


class KngetCommand(object):
    """Manage the commands of the KngetShell.
    """

    def __init__(self):
        self._commands = {}

    def register(self, argtypes=r'M', help_msg=None):
        """Register a method to a command.

        NOTE: Method registered here is unbound method,
              e.g. registered `run` command -> `KngetShell.run`
              So we call it should add `self` at first.

            See also: KngetShell.execute()

        :param argtypes: a str of the command args type.
            M: Myself -> self
            S: String -> str
            I: Integer -> int
        :param help_msg: a short help string of commands.
        :return: a callable function or method.
        """

        def format_args(method):
            def wrapped_method(*args, **kwargs):
                if len(args) != len(argtypes):
                    raise KngetError("args count is not equals to argtypes count.")

                # NOTE: We cannot modify the args.
                argv = []
                for i in range(len(argtypes)):
                    if argtypes[i] in ('m', 'M'):
                        argv.append(args[i])
                    elif argtypes[i] in ('i', 'I'):
                        argv.append(int(args[i]))
                    elif argtypes[i] in ('s', 'S'):
                        argv.append(str(args[i]))

                return method(*argv, **kwargs)

            self._commands[method.__name__] = (
                wrapped_method, help_msg
            )
            return wrapped_method

        # format_args first touch the method
        return format_args


class KngetShell(Knget):
    """KngetPy class extended for REPL.
    """

    # NOTE: `self.command` is same as `KngetShell.command`.
    #       So following this line, we use `self.command`
    #       replace the `KngetShell.command` in the methods.
    command = KngetCommand()

    def __init__(self):
        super(KngetShell, self).__init__()

    @command.register(argtypes=r'MSII', help_msg="<tags> <begin> <end>")
    def run(self, tags, begin, end):
        """Override method of class Knget
        """
        super(KngetShell, self).run(tags, begin, end)

    @command.register(argtypes=r'M', help_msg="exit this program.")
    def exit(self):
        sys.exit(_NO_ERROR)

    @command.register(argtypes=r'M', help_msg="login your account.")
    def login(self):
        self._login(**self._account)

    @command.register(argtypes=r'MS', help_msg="run a terminal command.")
    def runcmd(self, cmd_name):
        os.chdir(self._curdir)
        os.system(cmd_name)

    @command.register(argtypes=r'M', help_msg="show the debug info.")
    def debug(self):
        """Override method of `Knget._debug_info()`
        """
        self._debug_info()

    @command.register(argtypes=r'M', help_msg="reload the config.")
    def reload(self, config=None):
        self.load_config()
        self._session.headers = {
                'Accept': '*/*',
                'Connection': 'Keep-Alive',
                'User-Agent': self._custom.get('user_agent'),
        }

    @command.register(argtypes=r'M', help_msg="show this help again.")
    def help(self):
        print('Copyright (c) 2017-2018 urain39@cyfan.cf\n')
        print('Registered commands:')

        for cmd_name, cmd_itself in self.command._commands.items():
            _, help_msg = cmd_itself
            print(' ' * 4 + '{0:10s}{1}'.format(cmd_name, help_msg))

    @command.register(argtypes=r'MSSS', help_msg="<propkey> <propvalue>")
    def setprop(self, propkey, propvalue, valuetype):
        try:
            valuetype = valuetype[0]
            section, key = propkey.split('.')
            _section = getattr(self, '_' + section)

            if valuetype not in ('i', 's', 'I', 'S'):
                raise KngetError('Not support valuetype!',
                                 reason='valuetype is {0}'.format(valuetype))

            if key not in _section.keys():
                raise KngetError('Not found the key!',
                                 reason='key is {0}'.format(key))

            if valuetype in ('i', 'I'):
                _section[key] = int(propvalue)
            elif valuetype in ('s', 'S'):
                _section[key] = str(propvalue)
        except (ValueError, AttributeError) as e:
            self._msg2('Error: {0}'.format(e))

    @command.register(argtypes=r'MS', help_msg="print the property value.")
    def getprop(self, propkey):
        try:
            section, key = propkey.split('.')
            propvalue = getattr(self, '_' + section).get(key)
            self._msg2('PropValue: {0}'.format(propvalue))
        except (ValueError, AttributeError) as e:
            self._msg2('Error: {0}'.format(e))

    @command.register(argtypes=r'MS', help_msg="based on exec(), unsafe.")
    def dbgrun(self, source):
        """Debug run. based on exec(), unsafe.
        """
        try:
            exec(source)
        except Exception as e:
            self._msg2('Error: {0}'.format(e))

    def execute(self, lineno, cmd_name, args):
        if cmd_name not in self.command._commands.keys():
            self._msg2('#%d: Not found command %s\n' % (lineno, cmd_name))
            return self.help()
        else:
            # Unpack
            callback, help_msg = self.command._commands[cmd_name]

            try:
                # NOTE: callback is a unbound method, So we call
                #       the callback  should add the `self` at first.
                callback(self, *args)
            except (ValueError, OSError) as e:
                self._msg2('Error: {0}'.format(e))
                self._msg2('Usage: {0}'.format(help_msg))

    def session(self, message=_PROMPT_STR):
        lineno = 0

        if not sys.stdin.isatty():
            # Get input from a pipeline.
            while True:
                line = sys.stdin.read()
                lineno += 1

                if len(line) < 1:
                    break  # EOF
                line = shlex.split(line)

                if len(line) < 1:
                    continue  # Blank
                self.execute(lineno, cmd_name=line[0], args=line[1:])
        else:
            _session = PromptSession(message=message,
                                     history=InMemoryHistory())
            while True:
                line = _session.prompt()
                line = shlex.split(line)
                lineno += 1

                if len(line) < 1:
                    continue  # Blank

                try:
                    self.execute(lineno, cmd_name=line[0], args=line[1:])
                except (KngetError, TypeError, KeyboardInterrupt) as e:
                    self._msg2("Error: {0}".format(e))
                    if hasattr(e, '_reason') and e._reason is not None:
                        self._msg2("Reason: {0}".format(e._reason))
                    self._cleanup() # Ignore


def usage(status=None):
    print(_USAGE)

    if status is None:
        return
    else:
        sys.exit(status)


def main(argv):
    if len(argv) < 3:
        KngetShell().session()
    elif len(argv) == 3:
        KngetShell().run(argv[1], 1, argv[2])
    elif len(argv) == 4:
        KngetShell().run(argv[1], argv[2], argv[3])
    else:
        return usage(_USAGE_ERROR)


if __name__ == '__main__':
    try:
        main(sys.argv)
    except (KeyboardInterrupt, EOFError):
        sys.exit(_NO_ERROR)

