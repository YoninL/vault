package alibaba

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: []*framework.Path{
			pathConfig(),
			b.pathRole(),
			pathListRoles(&b),
			pathCreds(&b),
		},

		Secrets: []*framework.Secret{
			secretAccessKeys(&b),
		},

		WALRollback:       b.walRollback,
		WALRollbackMinAge: 5 * time.Minute,
		BackendType:       logical.TypeLogical,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The AWS backend dynamically generates AWS access keys for a set of
IAM policies. The AWS access keys have a configurable lease set and
are automatically revoked at the end of the lease.

After mounting this backend, credConfig to generate IAM keys must
be configured with the "root" path and policies must be written using
the "role/" endpoints before any access keys can be generated.
`
