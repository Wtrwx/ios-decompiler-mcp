# Tweak regression workflow

Use advanced primitives through `platform_tool`, requesting each required schema
on demand. Existing projects and the user's chosen build/deploy process take
precedence over creating a new project.

1. Inspect the real UI control and relevant runtime method/ivar. Do not infer a
   selector or ABI from its name. `ui_inspect_view`, `objc_get_methods` and
   `objc_get_method_implementation` supply observed evidence.
2. Check `tweak_environment` only when preparing a build. For a new project use
   `tweak_create_project`, `tweak_generate_hook`, and `tweak_validate_hook` with
   the observed class/encoding. Keep its bundle filter limited to the target app.
3. Build with `tweak_build`, inspect actual errors when it fails, and use the
   project's normal deployment flow. Preserve the existing deployment checks.
4. Verify the loaded image/build marker and the changed runtime/UI behavior.
   Exercise a small `ui_automate` batch with an assertion and one final capture.
   Use cursor-filtered logs only around the action being diagnosed.
5. Stop temporary log/trace hooks. Retain a session only while further work needs
   it; do not detach after every capture or repeatedly enumerate the app list.

Record failures separately: toolchain/build, install, injection, behavior and
automation support are distinct. When hardware is unavailable, keep local tests
and pending device checks explicit; mocks are not device performance evidence.
