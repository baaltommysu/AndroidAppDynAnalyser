#!/usr/bin/env bash

emulator -avd avd_test -system images/system23.img -ramdisk images/ramdisk23.img -kernel images/zImage23 -wipe-data -prop dalvik.vm.execution-mode=int:portable &
