package model

import (
	"github.com/jumpserver-dev/sdk-go/common"
)

type ConnectToken struct {
	Id       string     `json:"id"`
	User     User       `json:"user"`
	Value    string     `json:"value"`
	Account  Account    `json:"account"`
	Actions  Actions    `json:"actions"`
	Asset    Asset      `json:"asset"`
	Protocol string     `json:"protocol"`
	Domain   *Domain    `json:"domain"`
	Gateway  *Gateway   `json:"gateway"`
	ExpireAt ExpireInfo `json:"expire_at"`
	OrgId    string     `json:"org_id"`
	OrgName  string     `json:"org_name"`
	Platform Platform   `json:"platform"`

	ConnectMethod ConnectMethod `json:"connect_method"`

	ConnectOptions ConnectOptions `json:"connect_options"`

	CommandFilterACLs []CommandACL `json:"command_filter_acls"`
	
	DataMaskingRules []DataMaskingRule `json:"data_masking_rules"`
	
	Ticket           *ObjectId   `json:"from_ticket,omitempty"`
	TicketInfo       interface{} `json:"from_ticket_info,omitempty"`
	FaceMonitorToken string      `json:"face_monitor_token,omitempty"`

	Code   string `json:"code"`
	Detail string `json:"detail"`
	Error  string `json:"error"`
}

func (c *ConnectToken) CreateSession(addr string,
	loginFrom, SessionType LabelField) Session {
	return Session{
		User:      c.User.String(),
		Asset:     c.Asset.String(),
		Account:   c.Account.String(),
		Protocol:  c.Protocol,
		OrgID:     c.OrgId,
		UserID:    c.User.ID,
		AssetID:   c.Asset.ID,
		AccountID: c.Account.ID,
		DateStart: common.NewNowUTCTime(),

		RemoteAddr: addr,
		LoginFrom:  loginFrom,
		Type:       SessionType,
		ErrReason:  LabelField(SessionReplayErrUnsupported),
		TokenId:    c.Id,
	}
}

type ConnectTokenInfo struct {
	ID          string `json:"id"`
	Value       string `json:"value"`
	ExpireTime  int    `json:"expire_time"`
	AccountName string `json:"account_name"`
	Protocol    string `json:"protocol"`

	Ticket     *ObjectId  `json:"from_ticket,omitempty"`
	TicketInfo TicketInfo `json:"from_ticket_info,omitempty"`

	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

const (
	ACLReview = "acl_review"
	ACLReject = "acl_reject"

	ACLFaceVerify             = "acl_face_verify"
	ACLFaceOnline             = "acl_face_online"
	ACLFaceOnlineNotSupported = "acl_face_online_not_supported"
)

type ConnectOptions struct {
	Charset          *string `json:"charset,omitempty"`
	DisableAutoHash  *bool   `json:"disableautohash,omitempty"`
	BackspaceAsCtrlH *bool   `json:"backspaceAsCtrlH,omitempty"`
	Resolution       string  `json:"resolution"`

	FilenameConflictResolution string `json:"file_name_conflict_resolution,omitempty"`
	TerminalThemeName          string `json:"terminal_theme_name,omitempty"`
	Language                   string `json:"lang,omitempty"`

	// Sprint S11 / ADR-015: selective session recording. nil means "field
	// absent" (older Core, or endpoint that doesn't set it) — callers must
	// treat nil as true (record), never as false, so a missing hint never
	// silently reduces recording coverage below the pre-S11 baseline.
	ShouldRecord *bool `json:"should_record,omitempty"`

	// Sprint_43-Record-Session.md - Tier 0/1 "fail closed": if true, a
	// session that fails to initialize its recorder must be refused
	// rather than proceed unrecorded. Opposite fail-open default from
	// ShouldRecord above (nil -> false/not required) - an absent hint
	// (older Core) must never start refusing sessions that weren't
	// refused before.
	RecordingRequired *bool `json:"recording_required,omitempty"`
}

// ShouldRecordSession returns whether this session should be recorded.
// Fail-open by design (see ShouldRecord doc comment): a nil hint means
// "record", matching JumpServer's pre-S11 behavior.
func (o ConnectOptions) ShouldRecordSession() bool {
	return o.ShouldRecord == nil || *o.ShouldRecord
}

// IsRecordingRequired returns whether the session must be refused if
// recording can't be initialized. Fail-open by design: nil means "not
// required" (older Core never refuses a session over this).
func (o ConnectOptions) IsRecordingRequired() bool {
	return o.RecordingRequired != nil && *o.RecordingRequired
}

type ConnectMethod struct {
	Component string `json:"component"`
	Type      string `json:"type"`
	Label     string `json:"label"`
	Value     string `json:"value"`
}

// token 授权和过期状态

type TokenCheckStatus struct {
	Detail  string `json:"detail"`
	Code    string `json:"code"`
	Expired bool   `json:"expired"`
}

const (
	CodePermOk             = "perm_ok"
	CodePermAccountInvalid = "perm_account_invalid"
	CodePermExpired        = "perm_expired"
)

const ConnectApplet = "applet"
