# UIKit fixture

An operator-owned Objective-C application with `DecompilerFixtureViewController`, a label,
a button (`fixture.button`), and the target/action `buttonTapped:`. The initial
button title is `Original`. Each tap deterministically updates the label to `Tapped N`.
`viewDidAppear:` is an explicit lifecycle method suitable for the title-tweak recipe.
No accounts, network access, credentials or private data are needed.

Build using an installed Theos/iOS toolchain:

```sh
make -C examples/UIKitFixture clean package FINALPACKAGE=1 \
  CLANG_MODULE_CACHE_PATH="$PWD/.ios-decompiler-mcp/compiler-cache" \
  THEOS_PACKAGE_DIR="$PWD/.ios-decompiler-mcp/fixture-packages"
```

The example targets iOS 15+ and a rootless ARM64 application. Override `TARGET`,
`ARCHS` and `THEOS_PACKAGE_SCHEME` for another supported test environment.
The host must have a matching iOS SDK and signing tools.

An operator must explicitly authorize fixture installation on the test device;
this repository does not silently install it. Install its generated `.deb` with
your normal jailbreak package manager and refresh its application registration
using the jailbreak's documented procedure. Launch **Decompiler Fixture** once.

Configure SSH and Frida, allowlist `dev.iosdecompiler.fixture`, then run
`PYTHONPATH=src .venv/bin/python examples/demo.py --config ios-decompiler-mcp.local.toml --device test`.
The demonstration requests separate operator approvals for deployment/restart and
uninstallation/restart, and asserts that the final title is `Original`.
