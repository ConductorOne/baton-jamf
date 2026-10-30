package jamf

import (
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsNotFoundError reports whether err carries the gRPC NotFound code, which
// this package maps from an HTTP 404, e.g. deleting a user/account that no
// longer exists.
func IsNotFoundError(err error) bool {
	return status.Code(err) == codes.NotFound
}

// IsAlreadyExistsError reports whether err carries the gRPC AlreadyExists
// code, which this package maps from an HTTP 409, e.g. creating a user/account
// with a name that's already taken. Jamf also returns 409 for plain
// validation failures (malformed fields, invalid references), so a 409 is not
// proof the resource already exists — only treat it that way where the
// operation's semantics make "already exists" the sole realistic cause.
func IsAlreadyExistsError(err error) bool {
	return status.Code(err) == codes.AlreadyExists
}

// proEndpointError turns a 404 from a Jamf Pro API list endpoint into FailedPrecondition:
// the instance lacks the endpoint, and NotFound would make the SDK skip the sync action.
func proEndpointError(path string, err error) error {
	if IsNotFoundError(err) {
		return uhttp.WrapErrors(codes.FailedPrecondition, fmt.Sprintf("jamf pro api %s is not available on this Jamf Pro version", path), err)
	}
	return err
}
