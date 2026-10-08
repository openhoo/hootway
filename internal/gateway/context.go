package gateway

import "context"

func contextWith(ctx context.Context, info *requestInfo) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

func infoFrom(ctx context.Context) *requestInfo {
	info, _ := ctx.Value(ctxKey{}).(*requestInfo)
	if info == nil {
		return &requestInfo{rest: "/"}
	}
	return info
}
