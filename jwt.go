package jwtgrpc

import (
	"context"
	"github.com/go-funcards/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	userKey         = "user"
	tokenKey        = "token"
	authorizationMD = "authorization"
)

func HasUser(ctx context.Context) bool {
	_, ok := ctx.Value(userKey).(jwt.User)
	return ok
}

func GetUser(ctx context.Context) jwt.User {
	return ctx.Value(userKey).(jwt.User)
}

func GetUserID(ctx context.Context) string {
	return GetUser(ctx).UserID
}

func GetToken(ctx context.Context) string {
	return ctx.Value(tokenKey).(string)
}

func AppendToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, authorizationMD, token)
}

func FromContext(ctx context.Context, verifier jwt.Verifier) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values, ok := md[authorizationMD]
	if !ok || len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization token is not provided")
	}

	user, err := verifier.ExtractUser(values[0])
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "access token is invalid: %v", err)
	}

	ctx = context.WithValue(ctx, tokenKey, values[0])
	ctx = context.WithValue(ctx, userKey, user)

	return ctx, nil
}
