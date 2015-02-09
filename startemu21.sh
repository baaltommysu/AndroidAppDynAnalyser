#!/usr/bin/env bash

emulator -avd avd_test -system images/system21.img -ramdisk images/ramdisk21.img -kernel images/zImage21 -wipe-data -prop dalvik.vm.execution-mode=int:portable &
