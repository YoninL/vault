package alibaba

import (
	"context"
	"fmt"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathListRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: operationRolesList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathListRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: operationRolesList,
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func (b *backend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("user_group_name"),
		Fields: map[string]*framework.FieldSchema{
			"user_group_name": {
				Type:        framework.TypeString,
				Description: "Name of the user group",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fallback to the system/mount defaults.`,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.operationRoleCreateUpdate,
			logical.UpdateOperation: b.operationRoleCreateUpdate,
			logical.ReadOperation:   operationRoleRead,
			logical.DeleteOperation: operationRoleDelete,
		},
		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) operationRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userGroupName := data.Get("user_group_name").(string)

	role, err := readRole(ctx, req.Storage, userGroupName)
	if err != nil {
		return nil, err
	}
	if role == nil && req.Operation == logical.UpdateOperation {
		return nil, fmt.Errorf("no role found to update for %s", userGroupName)
	} else if role == nil {
		role = &roleEntry{}
	}

	if raw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(raw.(int)) * time.Second
	}

	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return nil, errors.New("ttl exceeds max_ttl")
	}

	entry, err := logical.StorageEntryJSON("role/"+userGroupName, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if role.TTL > b.System().MaxLeaseTTL() {
		resp := &logical.Response{}
		resp.AddWarning(fmt.Sprintf("ttl of %data exceeds the system max ttl of %data, the latter will be used during login", role.TTL, b.System().MaxLeaseTTL()))
		return resp, nil
	}
	return nil, nil
}

func operationRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := readRole(ctx, req.Storage, data.Get("user_group_name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"ttl":     role.TTL / time.Second,
			"max_ttl": role.MaxTTL / time.Second,
		},
	}, nil
}

func operationRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "role/"+data.Get("user_group_name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func operationRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func readRole(ctx context.Context, s logical.Storage, roleName string) (*roleEntry, error) {
	role, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	result := &roleEntry{}
	if err := role.DecodeJSON(result); err != nil {
		return nil, err
	}
	return result, nil
}

type roleEntry struct {
	TTL    time.Duration `json:"ttl"`
	MaxTTL time.Duration `json:"max_ttl"`
}

// TODO go through these descriptions
const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and reference RAM policies that access keys can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create access keys. These roles are associated with RAM policies that
map directly to the route to read the access keys. For example, if the
backend is mounted at "aws" and you create a role at "aws/roles/deploy"
then a user could request access credConfig at "aws/creds/deploy".

You can either supply a user inline policy (via the policy argument), or
provide a reference to an existing AWS policy by supplying the full arn
reference (via the arn argument). Inline user policies written are normal
IAM policies. Vault will not attempt to parse these except to validate
that they're basic JSON. No validation is performed on arn references.

To validate the keys, attempt to read an access key after writing the policy.
`
