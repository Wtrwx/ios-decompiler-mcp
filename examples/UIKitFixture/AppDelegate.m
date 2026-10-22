#import "AppDelegate.h"
#import "DecompilerFixtureViewController.h"

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [DecompilerFixtureViewController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end
