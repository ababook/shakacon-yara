rule shakacon2018jbradley: malz
{
	/*
		This is a rule of static indicators from a presentation shared at shakacon 2018
		Comments will  be updated with video link when available
	*/
	strings:
		$ip1 = "61.78.62.21"
		$ip2 = "61.78.62.102"
		$sha256a = "8029e7b12742d67fe13fcd53953e6b03ca4fa09b1d5755f8f8289eac08366efc" nocase
		$sha256b = "a5f7b13d0f259277e40e3711070121e451415d7d3a5e68382fc82c2fe3635db1" nocase
		$sha256c = "5b0cc5dd2897e697751b8204d8b74edd66466d651d233c76899c5521a60f6527" nocase
		$backdoorfn1 = "/usr/local/bin/google-updater"
		$backdoorfn2 = "/usr/local/bin/prl-monitor"
		$backdoorfn3 = "/usr/local/bin/git-lf"
		$backdoorfn4 = "/usr/local/sbin/nortonscanner"
		$backdoorfn5 = "/usr/local/plutil"
		$launchdaemon1 = "/Library/LaunchDaemons/com.apple.xsprinter.plist"
		$launchdaemon2 = "/System/Library/LaunchDaemons/com.apple.xsprinter.plist"

	condition:
		any of them
}
