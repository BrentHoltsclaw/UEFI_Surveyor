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

"""
The module can generate a list of EFI MM executables from (U)EFI firmware file

Usage:
  ``chipsec_main -m tools.uefi.scan_mmlist [-a fw_image]``
    - ``fw_image``	Full file path to UEFI firmware image.

Example:

>>> chipsec_main -i -n -m tools.uefi.scan_image -a uefi.rom

Creates a list of EFI MM executable binaries from ``uefi.rom``firmware binary

.. note::
    - ``-i`` and ``-n`` arguments can be used when specifying firmware file
      because the module doesn't depend on the platform and doesn't need kernel driver
"""

import os
from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
from chipsec.hal.uefi_fv import EFI_FILE, EFI_FV_FILETYPE_MM, EFI_FV_FILETYPE_COMBINED_MM_DXE
from chipsec.hal.uefi_fv import EFI_FV_FILETYPE_MM_CORE, EFI_FV_FILETYPE_MM_CORE_STANDALONE
from chipsec.hal.uefi_fv import EFI_FV_FILETYPE_MM_STANDALONE, FILE_TYPE_NAMES, EFI_SECTION, EFI_MODULE
from chipsec.hal.spi_uefi import build_efi_model, search_efi_tree, EFIModuleType
from chipsec.library.file import read_file, write_file
from collections import namedtuple

TAGS = [MTAG_BIOS]

OUTPATH = "/home/bh/devel/binaries/birchstream/MM_files"
WRITEFILES = True


class mmfile(namedtuple("mmfile", ['name', 'guid', 'fvtype', 'sha256hash'])):
    __slots__ = ()

    def __str__(self) -> str:
        return f'{self.name} {self.guid} {self.fvtype} {self.sha256hash}'


class scan_mmlist(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.efi_list = []
        self.suspect_modules = {}
        self.duplicate_list = []
        self.fvtypes = [EFI_FV_FILETYPE_MM_STANDALONE,
                        EFI_FV_FILETYPE_COMBINED_MM_DXE,
                        EFI_FV_FILETYPE_MM,
                        EFI_FV_FILETYPE_MM_CORE,
                        EFI_FV_FILETYPE_MM_CORE_STANDALONE]

    def is_supported(self):
        return True

    #
    # callback to match mm filetypes
    #
    def genmmfile_callback(self, efi_module: EFI_MODULE) -> None:
        if type(efi_module) == EFI_FILE:
            if efi_module.Type in self.fvtypes:
                self.efi_list.append(mmfile(efi_module.ui_string, efi_module.Guid, FILE_TYPE_NAMES[efi_module.Type], efi_module.SHA256))
                #Redo to add efi_module to list and then do the search at the higher level
                if WRITEFILES:
                    search_efi_tree([efi_module], self.writemmfile_callback, EFIModuleType.SECTION_EXE, True)

    def writemmfile_callback(self, efi_module: EFI_MODULE) -> None:
        if type(efi_module) == EFI_SECTION:
            fp = os.path.join(OUTPATH, f'{efi_module.parentGuid}_{efi_module.ui_string}')
            write_file(fp, efi_module.Image[efi_module.HeaderSize:])

    #
    # Generates new list of EFI executable binaries
    #
    def generate_efimmlist(self, file_pth: str) -> int:
        self.logger.log("[*] Generating a list of EFI executables from firmware image...")
        image = read_file(file_pth)
        efi_tree = build_efi_model(image, None)
        search_efi_tree(efi_tree, self.genmmfile_callback, EFIModuleType.FILE, True)
        self.logger.log(f'[*] Found {len(self.efi_list):d} EFI MM executables in UEFI firmware image \'{file_pth}\'')
        _orig_logname = self.logger.LOG_FILE_NAME
        self.logger.set_log_file('out.txt', False)
        for i in self.efi_list:
            self.logger.log(i)
        self.logger.set_log_file(_orig_logname)

    def usage(self):
        self.logger.log(__doc__.replace('`', ''))

    def run(self, module_argv):
        self.logger.start_test("Simple list mm module generation for (U)EFI firmware")
        op = 'generate' if len(module_argv) > 0 else 'help'
        if op in ['generate']:
            image_file = module_argv[0]
            self.logger.log(f'[*] Reading firmware from \'{image_file}\'...')
            self.generate_efimmlist(image_file)
        elif op == 'help':
            self.res = ModuleResult.NOTAPPLICABLE
            self.usage()
        else:
            self.logger.log_error("Unrecognized command-line argument to the module")
            self.usage()

        return self.res
