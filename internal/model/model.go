package model

type Tag struct {
	AuthID       string `json:"auth_id,omitempty"`
	Accounting   string `json:"accounting,omitempty"`
	EgressType   string `json:"egress_type,omitempty"`
	GrantTag     string `json:"grant_tag,omitempty"`
	RouteVersion string `json:"route_version,omitempty"`
	Identity     string `json:"identity,omitempty"`
	InboundTag   string `json:"inbound_tag,omitempty"`
	RouteReason  string `json:"route_reason,omitempty"`

	FallbackName   bool   `json:"-"`
	ExpiresAt      int64  `json:"expires_at,omitempty"`
	BillingDay     int    `json:"billing_day,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	AlertThreshold int    `json:"alert_threshold,omitempty"`
	PeriodStart    int64  `json:"period_start,omitempty"`

	Category        string   `json:"category"`
	Verification    string   `json:"verification"`
	DisplayEligible bool     `json:"display_eligible"`
	DisplayReason   string   `json:"display_reason"`
	TodayUpload     int64    `json:"today_upload"`
	TodayDownload   int64    `json:"today_download"`
	MonthUpload     int64    `json:"month_upload"`
	MonthDownload   int64    `json:"month_download"`
	Relations       []string `json:"relations,omitempty"`

	ID         string   `json:"id,omitempty"`
	RawTag     string   `json:"raw_tag,omitempty"`
	GlobalName string   `json:"global_name,omitempty"`
	NeedsName  bool     `json:"needs_name,omitempty"`
	Quota      int64    `json:"quota,omitempty"`
	MonthUsed  *int64   `json:"month_used"`
	Month      string   `json:"month"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Kind       string   `json:"kind"`
	Egress     string   `json:"egress"`
	Up         *float64 `json:"up"`
	Down       *float64 `json:"down"`
	Upload     *int64   `json:"upload"`
	Download   *int64   `json:"download"`
	Active     *int     `json:"active"`
	State      string   `json:"state"`
	Quality    string   `json:"quality"`
	IP         *Exit    `json:"ip"`
}
type Exit struct {
	MetadataCached bool   `json:"metadata_cached,omitempty"`
	MetadataAt     int64  `json:"metadata_at,omitempty"`
	IPType         string `json:"ip_type,omitempty"`
	Residential    *bool  `json:"residential,omitempty"`
	Datacenter     *bool  `json:"datacenter,omitempty"`
	RiskScore      *int   `json:"risk_score,omitempty"`
	QualityIP      string `json:"quality_ip,omitempty"`
	QualitySource  string `json:"quality_source,omitempty"`
	QualityAt      int64  `json:"quality_at,omitempty"`
	QualityError   string `json:"quality_error,omitempty"`

	Verified    bool   `json:"verified"`
	Attempted   int64  `json:"attempted"`
	City        string `json:"city"`
	CountryCode string `json:"country_code"`
	GeoSource   string `json:"geo_source"`
	Path        string `json:"path"`

	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
	Country string `json:"country"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
	Source  string `json:"source"`
	Updated int64  `json:"updated"`
	Error   string `json:"error,omitempty"`
}
type Host struct {
	CPU         *float64 `json:"cpu"`
	MemoryUsed  uint64   `json:"memory_used"`
	MemoryTotal uint64   `json:"memory_total"`
	DiskUsed    uint64   `json:"disk_used"`
	DiskTotal   uint64   `json:"disk_total"`
	Load        string   `json:"load"`
	Uptime      float64  `json:"uptime"`
	NetUp       *float64 `json:"net_up"`
	NetDown     *float64 `json:"net_down"`
	SingBox     bool     `json:"sing_box"`
}
type Discovery struct {
	Inbounds        int `json:"inbounds"`
	AuthIdentities  int `json:"auth_identities"`
	UnsupportedAuth int `json:"unsupported_auth"`
	Discovered      int `json:"discovered"`
	Reported        int `json:"reported"`
}
type Diagnostics struct {
	Discovery
	BackendVisible     int            `json:"backend_visible"`
	BackendFiltered    int            `json:"backend_filtered"`
	Authorized         int            `json:"authorized"`
	PermissionFiltered int            `json:"permission_filtered"`
	Reasons            map[string]int `json:"reasons"`
}
type Report struct {
	Discovery               *Discovery `json:"discovery,omitempty"`
	UnattributedConnections int        `json:"unattributed_connections,omitempty"`
	ServerID                string     `json:"server_id"`
	Epoch                   string     `json:"epoch"`
	Seq                     int64      `json:"seq"`
	At                      int64      `json:"at"`
	Interval                int        `json:"interval"`
	Host                    *Host      `json:"host"`
	Tags                    []Tag      `json:"tags"`
	Error                   string     `json:"error,omitempty"`
}
type View struct {
	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Online      bool         `json:"online"`
	Seen        int64        `json:"seen"`
	Report      *Report      `json:"report"`
}
