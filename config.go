package main

type ServerConfig struct {
	ServerId                   int        `json:"server_id"`
	DatabasePath               string     `json:"database_path"`
	Debug                      bool       `json:"debug"`
	WelcomeText                string     `json:"welcome_text"`
	Host                       string     `json:"host"`
	Port                       int        `json:"port"`
	AcceptProxyProtocol        bool       `json:"accept_proxy_protocol"`
	MaxBandwidth               int        `json:"bandwidth"`
	MaxUsers                   int        `json:"users"`
	MaxChannelUsers            int        `json:"max_channel_users"`
	MaxMultipleLoginCount      int        `json:"max_multiple_login_count"`
	MultiLoginLimitSameIP      bool       `json:"multilogin_same_ip"`
	AllowUDP                   bool       `json:"allow_udp"`
	AllowUDPVoice              bool       `json:"allow_udp_voice"`
	AllowPing                  bool       `json:"allow_ping"`
	MaxTextMessageLength       int        `json:"max_text_message_length"`
	MaxImageMessageLength      int        `json:"max_image_message_length"`
	AllowHTML                  bool       `json:"allow_html"`
	Publish                    bool       `json:"publish"`
	RegisterName               string     `json:"register_name"`
	RegisterPassword           string     `json:"register_password"`
	RegisterUrl                string     `json:"register_url"`
	RegisterHostname           string     `json:"register_hostname"`
	RegisterLocation           string     `json:"register_location"`
	SSLCert                    string     `json:"ssl_cert"`
	SSLKey                     string     `json:"ssl_key"`
	CertRequired               bool       `json:"cert_required"`
	SendVersion                bool       `json:"send_version"`
	Timeout                    int        `json:"timeout"`
	RequiredGroup              [][]string `json:"required_group"`
	DirectVoiceBehavior        string     `json:"direct_voice_behavior"` // Enum: vanilla(default) local block
	MinClientVersion           int        `json:"min_client_version"`
	RequireClientPlatformInfo  bool       `json:"require_client_platform_info"`
	SendBuildInfo              bool       `json:"send_build_info"`
	APIUrl                     string     `json:"api_url"`
	APIKey                     string     `json:"api_key"`
	APIInsecure                bool       `json:"api_insecure"`
	TrustedProxies             []string   `json:"trusted_proxies"`
	DefaultChannel             int        `json:"default_channel"`
	OpusThreshold              int        `json:"opus_threshold"`
	SuggestVersion             int        `json:"suggest_version"`
	SuggestPositional          *bool      `json:"suggest_positional"`
	SuggestPushToTalk          *bool      `json:"suggest_ptt"`
	CheckLastChannelPermission bool       `json:"check_last_channel_permission"`
	UDPBufferSize              int        `json:"udp_buffer_size"`
	AllowGuest                 bool       `json:"allow_guest"`
	UDPMarkUnstableRate        float64    `json:"udp_mark_unstable_rate"`
	UseOfflineCache            bool       `json:"use_offline_cache"`
	AllowRecording             bool       `json:"allow_recording"`
	SendPermissionInfo         bool       `json:"send_permission_info"`
	AclCacheSize               int        `json:"acl_cache_size"`
}
