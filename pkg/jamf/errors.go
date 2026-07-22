package jamf

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsNotFoundError reports whether err came from a Jamf API response mapped to
// a 404, e.g. deleting a user/account that no longer exists.
func IsNotFoundError(err error) bool {
	return status.Code(err) == codes.NotFound
}

// IsAlreadyExistsError reports whether err came from a Jamf API response
// mapped to a 409 Conflict, e.g. creating a user/account with a name that's
// already taken.
func IsAlreadyExistsError(err error) bool {
	return status.Code(err) == codes.AlreadyExists
}
