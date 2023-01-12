#!/usr/bin/env python

"""
async logger
"""

import os
import sys
import time
import json
import queue
import datetime
import threading
from enum import IntEnum

__author__ = "yun"
__copyright__ = ""
__credits__ = [""]
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


class LogLevel(IntEnum):
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    FATAL = 5


class _AsyncLogger(threading.Thread):

    staticLoggerNum = 0

    def __init__(self, file_path):
        threading.Thread.__init__(self)
        _AsyncLogger.staticLoggerNum = self.staticLoggerNum + 1
        self.file_path = file_path
        self.flag_running = False
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        self.interval = 0.10
        self.condition = threading.Condition()

    def run(self):
        self.flag_running = True

        try:
            if self.file_path == "":
                out_file = sys.stdout
            else:
                out_file = open(self.file_path, "w")
        except FileNotFoundError as e:
            print(f"{e}, {self.file_path}")
            return

        while self.flag_running:
            self.condition.acquire()

            while self.queue.empty():
                self.condition.wait(0.1)
                if not self.flag_running:
                    break

            if not self.flag_running:
                break
            new_tuple = self.queue.get(timeout=0.1)
            machine_datetime = datetime.datetime.now()
            if self.file_path == "":
                context = {'time': machine_datetime.strftime("%Y%m%d-%H:%M:%S.%f"),
                           'function': new_tuple[1],
                           'level': new_tuple[0].name,
                           'namespace': new_tuple[2],
                           'message': new_tuple[3]}
                line = json.dumps(context)
                line = f'{line}\n'
            else:
                # level, func_name, namespace, new_msg
                line = '{}|{}|{}:{} - {}\n'.format(machine_datetime.strftime("%Y%m%d-%H:%M:%S.%f"),
                                                   new_tuple[0].name,
                                                   new_tuple[2],
                                                   new_tuple[1],
                                                   new_tuple[3])
            out_file.write(line)
            out_file.flush()

            self.condition.release()

        if self.file_path != "":
            out_file.close()
        print('Logging stopped')

    def logging(self, level, func_name, namespace, new_msg):
        self.condition.acquire()
        self.queue.put((level, func_name, namespace, new_msg))
        self.condition.notify()
        self.condition.release()

    def stop(self):
        self.lock.acquire()
        try:
            self.flag_running = False
            self.condition.acquire()
            self.condition.notify()
            self.condition.release()
        finally:
            self.lock.release()


class AsyncLogger(object):

    def __init__(self, path, prefix, namespace=''):
        self.instance = None
        self.file_path = path
        self.file_name = self.set_logging_prefix(prefix)
        self.namespace = namespace
        self.lock = threading.Lock()

    def set_logging_path(self, new_path):
        self.file_path = new_path

    def set_logging_prefix(self, prefix):
        if self.file_path == "":
            filename = ""
        else:
            os.makedirs(self.file_path, exist_ok=True)
            filename = prefix + '_' + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + '.log'
            filename = os.path.join(self.file_path, filename)
        return filename

    def start_log(self,):
        with self.lock:
            if not self.instance:
                self.instance = _AsyncLogger(self.file_name)
                self.instance.start()

    def logging(self, level, new_msg):
        try:
            func_name = sys._getframe(1).f_code.co_name
        except ValueError:
            func_name = 'NONE'
        self.instance.logging(level, func_name, self.namespace, new_msg)

    def debug(self, new_msg):
        try:
            func_name = sys._getframe(1).f_code.co_name
        except ValueError:
            func_name = 'NONE'
        self.instance.logging(LogLevel.DEBUG, func_name, self.namespace, new_msg)

    def info(self, new_msg):
        try:
            func_name = sys._getframe(1).f_code.co_name
        except ValueError:
            func_name = 'NONE'
        self.instance.logging(LogLevel.INFO, func_name, self.namespace, new_msg)

    def warning(self, new_msg):
        try:
            func_name = sys._getframe(1).f_code.co_name
        except ValueError:
            func_name = 'NONE'
        self.instance.logging(LogLevel.WARNING, func_name, self.namespace, new_msg)

    def error(self, new_msg):
        try:
            func_name = sys._getframe(1).f_code.co_name
        except ValueError:
            func_name = 'NONE'
        self.instance.logging(LogLevel.ERROR, func_name, self.namespace, new_msg)

    def fatal(self, new_msg):
        try:
            func_name = sys._getframe(1).f_code.co_name
        except ValueError:
            func_name = 'NONE'
        self.instance.logging(LogLevel.FATAL, func_name, self.namespace, new_msg)

    def logging_multi(self, level, *args):
        try:
            func_name = sys._getframe(1).f_code.co_name
        except ValueError:
            func_name = 'NONE'

        for cur in args:
            self.instance.logging(level, func_name, self.namespace, cur)

    def stop_log(self):
         if self.instance:
             self.instance.stop()


if __name__ == "__main__":
    logger = AsyncLogger('', prefix='test')
    logger.start_log()
    for i in range(0, 100):
        if i % 3 == 0:
            logger.logging(LogLevel.DEBUG, str(i))
        elif i % 3 == 1:
            logger.logging(LogLevel.WARNING, str(i))
        elif i % 3 == 2:
            logger.logging(LogLevel.ERROR, str(i))
    time.sleep(1)
    logger.stop_log()
