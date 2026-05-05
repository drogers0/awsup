package settings

import (
	"context"
	"fmt"

	"github.com/drogers0/awsup/internal/appsync"
)

// Settings holds the TEAM deployment-wide configuration retrieved from AppSync.
type Settings struct {
	ID                        string `json:"id"`
	Duration                  string `json:"duration"`
	Expiry                    string `json:"expiry"`
	Comments                  bool   `json:"comments"`
	TicketNo                  bool   `json:"ticketNo"`
	Approval                  bool   `json:"approval"`
	ModifiedBy                string `json:"modifiedBy"`
	SesNotificationsEnabled   bool   `json:"sesNotificationsEnabled"`
	SnsNotificationsEnabled   bool   `json:"snsNotificationsEnabled"`
	SlackNotificationsEnabled bool   `json:"slackNotificationsEnabled"`
	TeamAdminGroup            string `json:"teamAdminGroup"`
	TeamAuditorGroup          string `json:"teamAuditorGroup"`
	UseOUCache                bool   `json:"useOUCache"`
	CreatedAt                 string `json:"createdAt"`
	UpdatedAt                 string `json:"updatedAt"`
}

const getSettingsQuery = `
query GetSettings($id: ID!) {
  getSettings(id: $id) {
    id duration expiry comments ticketNo approval modifiedBy
    sesNotificationsEnabled snsNotificationsEnabled slackNotificationsEnabled
    teamAdminGroup teamAuditorGroup useOUCache createdAt updatedAt __typename
  }
}`

type getSettingsVars struct {
	ID string `json:"id"`
}

type getSettingsData struct {
	GetSettings *Settings `json:"getSettings"`
}

// Get fetches the singleton settings record (id="settings") from AppSync.
func Get(ctx context.Context, c *appsync.Client) (*Settings, error) {
	data, err := appsync.Execute[getSettingsData](ctx, c, getSettingsQuery, getSettingsVars{ID: "settings"})
	if err != nil {
		return nil, fmt.Errorf("getSettings: %w", err)
	}
	if data.GetSettings == nil {
		return nil, fmt.Errorf("getSettings returned null")
	}
	return data.GetSettings, nil
}
