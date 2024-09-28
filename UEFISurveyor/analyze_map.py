# Copyright 2024 Intel Corporation
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
#
# This script identifies module entry point and labels
# efi specific functions, protocols, and guids
# @category UEFISurveyor.headless

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.disassemble import Disassembler
from ghidra.app.plugin.core.analysis import AutoAnalysisManager


from hash import fnHashes
from logger import logger
from artifacts import artifacts
from guids import guids
from EFI_functs import EFIUtils
from analytics import EFIAnalytics

import sys


if __name__ == "__main__":
    fileName = getProgramFile().toString()
    logger().enableLogFile('{}.log'.format(fileName))
    logger().log("Attempting to Analyze {}".format(fileName))

    # initialize GhidraUtils class
    EFIUtil = EFIUtils(currentProgram)

    # load map file
    args = getScriptArgs()
    logger().log("Args passed in: {}".format(args))
    if len(args) > 0:
        mapfile = args[0]
    else:
        logger().log('Missing Map file!')
        sys.exit()

    # Search for Entry Points
    eps = EFIUtil.findModuleEntries()

    # ensure Decompiler Parameter ID is enabled
    setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true")

    # Disassemble the entry points
    ctMon = ConsoleTaskMonitor()
    dis = Disassembler.getDisassembler(currentProgram, ctMon, None)
    for entry in eps:
        disAddrs = dis.disassemble(entry, None)
        AutoAnalysisManager.getAnalysisManager(currentProgram).codeDefined(disAddrs)
        AutoAnalysisManager.getAnalysisManager(currentProgram).waitForAnalysis(None, ctMon)

    # label Possible Functions
    EFIUtil.labelPossibleUndefinedFunctions()

    # Label Functions via Map File
    EFIUtil.labelMapFunctions(mapfile)

    EFIAnalytic = EFIAnalytics(currentProgram)

    # log the functions and hashes
    EFIAnalytic.getFunctionHashes(fileName)

    logger().closeLogFile()
