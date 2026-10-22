ARCHS ?= arm64
TARGET ?= iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME ?= rootless

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = FLEXFixture
FLEXFixture_FILES = main.m AppDelegate.m FLEXFixtureViewController.m
FLEXFixture_FRAMEWORKS = UIKit Foundation
FLEXFixture_CFLAGS = -fobjc-arc
FLEXFixture_RESOURCE_DIRS = Resources
FLEXFixture_CODESIGN_FLAGS = -SEntitlements.plist

include $(THEOS_MAKE_PATH)/application.mk
