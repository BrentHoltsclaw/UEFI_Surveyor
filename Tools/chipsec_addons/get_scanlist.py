# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from argparse import ArgumentParser
from collections import namedtuple
import os
import subprocess
import sys


class mmhandler(namedtuple("mmhandler", ['name', 'guid', 'handlers'])):
    __slots__ = ()

    def __str__(self) -> str:
        return f'{self.name}  {self.guid}\n{"".join(handler for handler in self.handlers)}'


def getMM(chipsecPath, binPath):
    command = ['python3', os.path.join(chipsecPath, 'chipsec_main.py'),
               '-nb',
               '-n',
               '--skip_config',
               '-i',
               '-I',
               '.',
               '-m',
               'scan_mmlist',
               '-a',
               binPath]
    proc = subprocess.run(command)
    if proc.returncode != 0:
        return False
    return True


def getHandlers(analysisPath):
    something = []
    with open('out.txt', 'r') as f:
        for line in f:
            sections = line.split(' ')
            print(sections)
            fname = f'{sections[1]}_{sections[0]}.json'
            fpath = os.path.join(analysisPath, fname)
            handlers = []
            with open(fpath, 'r') as fnfile:
                for fnline in fnfile:
                    if 'handler' in fnline.lower():
                        handlers.append(fnline.split(':')[0].replace('"', "").replace(",", ''))
            something.append(mmhandler(sections[0], sections[1], handlers))
    with open('report.txt', 'w') as report:
        for i in something:
            report.writelines(str(i))


if __name__ == '__main__':
    parser = ArgumentParser(prog='chipsecAddons')
    subparsers = parser.add_subparsers()

    # get MM files from binary
    mmfiles = subparsers.add_parser('getMM')
    mmfiles.add_argument('arg1', metavar='chipsecPath', type=str, help='filepath to CHIPSEC')
    mmfiles.add_argument('arg2', metavar='binPath', type=str, help='filepath of binary')
    mmfiles.set_defaults(func=getMM)

    # add Handlers to output
    handlers = subparsers.add_parser('getHandlers')
    handlers.add_argument('arg1', metavar='analysisPath', type=str, help='filepath to Ghidra Analyzed files')
    handlers.set_defaults(func=getHandlers)

    args = parser.parse_args(sys.argv[1:])
    if sys.argv[1] == 'getMM':
        args.func(args.arg1, args.arg2)
    elif sys.argv[1] == 'getHandlers':
        args.func(args.arg1)
    else:
        parser.parse_args(['help'])
