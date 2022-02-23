//go:build lang_zh
// +build lang_zh

package main

// English

const (
	trnDirectVoiceBlock             = "<strong>警告:</strong> 您的按键发言设置有错误，您应该使用<b>密语/呼喊</b>快捷键设置，即本地按键（黄麦）。我们已经将您禁言，请完成配置后重新连接服务器。配置方法详见<a href=\"https://wiki.winterco.org/zh:%E6%95%99%E7%A8%8B:it:mumble#%E5%BF%AB%E6%8D%B7%E9%94%AE%E8%AE%BE%E7%BD%AE\">联盟百科相关条目</a>"
	trnCertRequired                 = "您必须生成一个证书才能连接这个服务器。电脑用户可使用上方“配置”栏中证书向导的自动生成证书功能，或联系军团总监协助设置"
	trnInvalidUsername              = "请输入一个有效的用户名"
	trnAuthenticatorFail            = "后台暂时无法验证您的用户名和密码，请稍后再试"
	trnAuthenticatorNoUser          = "未找到该用户"
	trnAuthenticatorInvalidCred     = "用户名或密码错误，有疑问请联系军团总监"
	trnRequiredGroupNotMet          = "您无权连接此服务器。请联系联盟管理确认您的权限"
	trnSimultaneousLoginDifferentIP = "您只能在同一 IP 地址下多开登录"
	trnTooManySimultaneousLogin     = "您已经超出同时多开的最大数量，请关闭一些客户端或检查密码是否泄露"
	trnNoCELTSupport                = "<strong>警告:</strong> 您的客户端版本过低，不支持 CELT 编码方式，因此你将无法听到大多数人讲话。请及时升级到最新版本"
	trnNoOpusSupport                = "<strong>警告:</strong> 您的客户端版本过低，不支持 Opus 编码方式，因此你将无法听到大多数人讲话。请及时升级到最新版本"
	trnVersionTooOld                = "您的客户端未达到服务器要求的最低版本限制，请下载安装最新版本"
	trnServerIsFull                 = "服务器已满员"
	trnPlatformInfoMissing          = "您的客户端设置存在安全风险，请恢复到出厂设置并重新调整"
)
