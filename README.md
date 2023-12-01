# WHMCS License Bypass with Updates (License.php)

I am pleased to share the result of my recent complete update project for the License.php file in WHMCS. Although it was a challenge, I enjoyed every moment dedicated to researching and simplifying the solution. Over the years, I have contributed significantly to this community, and despite my attempts to report this issue to WHMCS, the response was not positive. For this reason, I decided to share this solution with those who wish to use this incredible software for their projects

![Force Check](https://github.com/jesussuarz/whmcs-nulled-license-full-update/blob/main/img/force_license.png?raw=true)

How does it work? Simply replace the License.php file in the location of your WHMCS installation, either before or after installing the software. The path is:

```
/vendor/whmcs/whmcs-foundation/lib/License.php
```
**This license file is designed for versions higher than v8.8.x.**

Feel free to enter any license number both during the initial installation and after installing it in the configuration.php file. Everything is verified with the License.php file.

I reiterate, with this solution, you can have a FULL WHMCS with all official WHMCS updates. (You can review the code; my approach was to maintain almost all original validations and adjust only what was necessary for the software to believe it has a valid license. However, all validations are performed with WHMCS servers.):

```
    const LICENSE_API_HOSTS = ["a.licensing.whmcs.com", "b.licensing.whmcs.com", "c.licensing.whmcs.com", "d.licensing.whmcs.com", "e.licensing.whmcs.com", "f.licensing.whmcs.com"];
    const STAGING_LICENSE_API_HOSTS = ["hou-1.licensing.web.staging.whmcs.com"];
```

![Check Update](https://github.com/jesussuarz/whmcs-nulled-license-full-update/blob/main/img/update_check.png?raw=true)

If you have any questions or concerns, feel free to open an issue at: https://github.com/jesussuarz/whmcs-nulled-license-full-update/issues (I will address any issue as soon as possible.). You can also raise the problem in Spanish.

Please note that you can obtain official versions only at the following link: https://s3.amazonaws.com/releases.whmcs.com/v2/pkgs/whmcs-8.8.0-release.1.zip (Just change the release version, and you will get versions without any modifications.)

Finally, I want to express my special thanks to the team at https://easytoyou.eu/ and, in particular, to "Miguel" for providing their services to decrypt the latest version of the WHMCS license file, making this project possible.

For more details about this project, you can visit my post on LinkedIn: https://www.linkedin.com/posts/jesussuarz_github-jesussuarzwhmcs-nulled-license-full-update-activity-7132283748267503616-N8wx

