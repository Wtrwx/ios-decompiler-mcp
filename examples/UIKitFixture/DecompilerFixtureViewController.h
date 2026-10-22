#import <UIKit/UIKit.h>

@interface DecompilerFixtureViewController : UIViewController
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *button;
@property (nonatomic) NSUInteger tapCount;
- (void)buttonTapped:(UIButton *)sender;
@end
