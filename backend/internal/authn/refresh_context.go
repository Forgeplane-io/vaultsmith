package authn

import "context"

type sessionlessContext struct {
	context.Context
}

func (sessionlessContext) Value(any) any {
	return nil
}

func contextWithoutSession(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return sessionlessContext{Context: ctx}
}
