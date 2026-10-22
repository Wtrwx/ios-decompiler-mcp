#import "AppDelegate.h"
#import "FLEXFixtureViewController.h"

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [FLEXFixtureViewController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end
