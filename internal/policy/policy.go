package policy

import (
	"context"
	"fmt"

	"github.com/drogers0/awsup/internal/appsync"
)

// Account represents an AWS account the user may request access to.
type Account struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Permission represents a permission set the user may request.
type Permission struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Policy holds the set of accounts and permission sets a user is entitled to
// request, along with request parameters.
type Policy struct {
	Accounts         []Account    `json:"accounts"`
	Permissions      []Permission `json:"permissions"`
	ApprovalRequired bool         `json:"approvalRequired"`
	Duration         int          `json:"duration"`
}

// UserPolicy is the top-level response type. Policy is nil for direct-grant
// users (not an error).
type UserPolicy struct {
	ID       string  `json:"id"`
	Username string  `json:"username"`
	Policy   *Policy `json:"policy"`
}

const getUserPolicyQuery = `
query GetUserPolicy($userId: String, $groupIds: [String]) {
  getUserPolicy(userId: $userId, groupIds: $groupIds) {
    id
    policy {
      accounts { name id __typename }
      permissions { name id __typename }
      approvalRequired
      duration
      __typename
    }
    username
    __typename
  }
}`

type getUserPolicyVars struct {
	UserID   string   `json:"userId"`
	GroupIDs []string `json:"groupIds"`
}

type getUserPolicyData struct {
	GetUserPolicy *UserPolicy `json:"getUserPolicy"`
}

// Get fetches the user's policy from AppSync. It returns a UserPolicy whose
// Policy field may be nil for direct-grant users.
func Get(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*UserPolicy, error) {
	vars := getUserPolicyVars{UserID: userID, GroupIDs: groupIDs}
	data, err := appsync.Execute[getUserPolicyData](ctx, c, getUserPolicyQuery, vars)
	if err != nil {
		return nil, fmt.Errorf("getUserPolicy: %w", err)
	}
	if data.GetUserPolicy == nil {
		return nil, fmt.Errorf("getUserPolicy returned null")
	}
	return data.GetUserPolicy, nil
}
