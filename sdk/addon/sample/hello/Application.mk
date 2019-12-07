ANODE_ROOT       := /Users/jiayq/Downloads/Source/anode
NODE_ROOT    := /Users/jiayq/Downloads/Source/node

APP_MODULES      := hello
APP_ABI          := armeabi
NDK_MODULE_PATH  := $(NDK_MODULE_PATH):$(ANODE_ROOT):$(ANODE_ROOT)/..:$(NODE_ROOT):$(NODE_ROOT)/..


APP_PROJECT_PATH :=.
APP_BUILD_SCRIPT :=$(APP_PROJECT_PATH)/Android.mk
APP_PLATFORM     := android-9
APP_STL          := stlport_static