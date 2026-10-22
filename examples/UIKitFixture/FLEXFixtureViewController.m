#import "FLEXFixtureViewController.h"

@implementation FLEXFixtureViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.view.accessibilityIdentifier = @"fixture.root";

    self.statusLabel = [UILabel new];
    self.statusLabel.text = @"Ready";
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.accessibilityIdentifier = @"fixture.status";
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.statusLabel];

    self.button = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.button setTitle:@"Original" forState:UIControlStateNormal];
    self.button.accessibilityIdentifier = @"fixture.button";
    self.button.translatesAutoresizingMaskIntoConstraints = NO;
    [self.button addTarget:self action:@selector(buttonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.button];

    [NSLayoutConstraint activateConstraints:@[
        [self.button.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.button.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [self.button.widthAnchor constraintEqualToConstant:220],
        [self.button.heightAnchor constraintEqualToConstant:52],
        [self.statusLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.statusLabel.bottomAnchor constraintEqualToAnchor:self.button.topAnchor constant:-24],
    ]];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    self.statusLabel.text = @"Ready";
}

- (void)buttonTapped:(UIButton *)sender {
    self.tapCount += 1;
    self.statusLabel.text = [NSString stringWithFormat:@"Tapped %lu", (unsigned long)self.tapCount];
}
@end
