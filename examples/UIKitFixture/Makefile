ARCHS ?= arm64
TARGET ?= iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME ?= rootless

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = DecompilerFixture
DecompilerFixture_FILES = main.m AppDelegate.m DecompilerFixtureViewController.m
DecompilerFixture_FRAMEWORKS = UIKit Foundation
DecompilerFixture_CFLAGS = -fobjc-arc
DecompilerFixture_RESOURCE_DIRS = Resources
DecompilerFixture_CODESIGN_FLAGS = -SEntitlements.plist

include $(THEOS_MAKE_PATH)/application.mk
