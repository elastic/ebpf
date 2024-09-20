package testrunner

import (
	"context"
	"io"
)

type ctxRdr struct {
	ctx context.Context
	r   io.Reader
}

func NewContextReader(ctx context.Context, reader io.ReadCloser) io.Reader {
	return &ctxRdr{ctx: ctx, r: reader}
}

func (r *ctxRdr) Read(p []byte) (n int, err error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.r.Read(p)
	}
}
