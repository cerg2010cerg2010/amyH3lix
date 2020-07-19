# sockH3lix

Jailbreak for iOS 10.x 64bit devices without KTRR

Replace the exploit from v0rtex to [sock port](https://github.com/jakeajames/sock_port) by Jake James with higher success rate and shorter time.

Kernel patches and other resources are inherited from doubleH3lix.

Only test on my 5s(10.3.3). 10.x 64bit devices is supported in theory. Use at your own risk.

This jailbreak tool is compatible with doubleH3lix, which means you can switch between them at any time.

Latest fix: 
- Remove a sandbox kernel patch which causes error container path achieved during sandbox_container_path_for_pid syscall, and eventually causes NSUserDefaults(cfprefsd) to write thie plist to the unsandbox path /var/mobile/Library/Preferences. However, removing this patch cause the "run uicache" in app failed to work. 
- H3lix is not open source. A binary-patched version without such sandbox kernel patch can be achieved at [here](https://github.com/SongXiaoXi/sockH3lix/releases). Special thanks to Jake James' [script](https://gist.github.com/jakeajames/b44d8db345769a7149e97f5e155b3d46) for removing DRM.

PS: 
- As far as I understand, this may not be a bug, the entire sandbox (including sandbox applications) has been patched. This may cause some security problems. Both files provided above disable this patch.
