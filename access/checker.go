package access

import "context"

type Checker interface {
	ValidateWithContext(ctx context.Context) error
}

type checks []Checker

func (cs checks) ValidateWithContext(ctx context.Context) error {
	for _, c := range cs {
		err := c.ValidateWithContext(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func Merge(checkers ...Checker) Checker {
	return checks(checkers)
}

type PermissionError struct {
	error
}
