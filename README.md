# sockH3lix

Jailbreak for iOS 10.x 64bit devices without KTRR

**Replace the exploit from v0rtex to [sock port](https://github.com/jakeajames/sock_port) with higher success rate and shorter time.**

Kernel patches and other resources are inherited from doubleH3lix.

**Only test on my 5s (10.3.3).** 10.x 64bit KPP devices is supported in theory. **Use at your own risk.**

This jailbreak tool is compatible with doubleH3lix, which means you can switch between them at any time.

## Additional modifications:
- Exploit
  - v0rtex -> sock port with higher success rate.
- Sandbox
  - Remove a patch which fully disable sandbox for any process. This keeps sandbox container intact and avoids NSUserDefaults (cfprefsd) stores plist in the unsandbox path.
  - H3lix is not open source. A binary-patched version without such sandbox patch can be achieved at [here](https://github.com/SongXiaoXi/sockH3lix/releases). Special thanks to Jake James' [script](https://gist.github.com/jakeajames/b44d8db345769a7149e97f5e155b3d46) for removing DRM.
  - sockH3lix will call uicache with sock port exploit for sandbox escaping. Closed-source H3lix without such sandbox path cannot use uicache.
- export tfp0
  - Enable hgsp4 for root process.
