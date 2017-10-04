#!/usr/bin/env python

#
# Copyright 2017 Staffan Friberg, Medallia
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

from __future__ import print_function
from bcc import BPF
from subprocess import call
import time, os
import ctypes
import argparse
import psutil

parser = argparse.ArgumentParser(description="Sample allocation in a Java application using Linux Perf and eBPF")
parser.add_argument("-d", "--duration", default=10, type=int, help="Duration of sampling")
parser.add_argument("-j", "--jdk", help="Location of JDK, by default use same as attached process")
parser.add_argument("pid", type=int, help="PID of Java application instance to sample")
args = parser.parse_args()

def exit_with_help(reason):
    print(reason)
    parser.print_help()
    exit(1)
    
try:
    process = psutil.Process(pid=args.pid)
except psutil.NoSuchProcess as e:
    exit_with_help("Unable to find pid: %d" % args.pid)

if not args.jdk:
    jdk_home = os.path.dirname(os.path.dirname(os.path.dirname(process.exe())))
    java_exe = process.exe()
else:
    jdk_home = args.jdk
    java_exe = args.jdk + "/bin/java"
libjvm = jdk_home + "/jre/lib/amd64/server/libjvm.so"

if not (os.path.exists(libjvm) and os.path.exists(java_exe)):
    exit_with_help("Unable to find JDK at %s" % jdk_home)

if not (os.path.exists("attach-main.jar") and os.path.exists("libperfmap.so")):
    exit_with_help("Ensure perf-map-agent is copied to the same directory as the scripts")

class Key(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint),
                ("stack_id", ctypes.c_ulonglong)]

class Data(ctypes.Structure):
    _fields_ = [("count", ctypes.c_ulonglong),
                ("tlab_size", ctypes.c_ulonglong),
                ("size", ctypes.c_ulonglong),
                ("type", ctypes.c_char * 64)]

b = BPF(src_file="allocation-bcc.c")

b.attach_uprobe(name=libjvm,
                sym="_ZN11AllocTracer34send_allocation_outside_tlab_eventE11KlassHandlem",
                fn_name="alloc_outside_tlab",
                pid=process.pid)

b.attach_uprobe(name=libjvm,
                sym="_ZN11AllocTracer33send_allocation_in_new_tlab_eventE11KlassHandlemm",
                fn_name="alloc_in_new_tlab",
                pid=process.pid)

time.sleep(args.duration)

call(["sudo", "-u", process.username(), java_exe,
      "-cp", "attach-main.jar:%s/lib/tools.jar" % jdk_home,
      "net.virtualvoid.perf.AttachOnce", "%s" % process.pid])

stacks = b.get_table("stacks")
allocation = b.get_table("allocation")

for c_key, c_data in allocation.items():
    key = ctypes.cast(ctypes.pointer(c_key), ctypes.POINTER(Key)).contents
    data = ctypes.cast(ctypes.pointer(c_data), ctypes.POINTER(Data)).contents

    print("Type: %s Count: %d" % (data.type, data.count))
    print(" Total TLAB Size: %d bytes, Avg TLAB Size %d bytes" % (data.tlab_size, data.tlab_size/data.count))
    print(" Total Object Size: %d bytes, Avg Object Size %d bytes" % (data.size, data.size/data.count))
    print(" Stacktrace:")
    for addr in stacks.walk(key.stack_id):
        print("\t%s" % b.sym(addr, key.pid, show_offset=True))
    print("")
