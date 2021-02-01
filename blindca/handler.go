package blindca

import (
	"github.com/vocdoni/multirpc/router"
	"github.com/vocdoni/multirpc/transports/mhttp"
	"go.vocdoni.io/dvote/log"
)

// SignatureReq is the signature request handler.
// It executes the AuthCallback function to allow or deny the request to the client.
func (ca *BlindCA) SignatureReq(rr router.RouterRequest) {
	msg := &BlindCA{}
	httpctx, ok := rr.MessageContext.(*mhttp.HttpContext)
	if !ok {
		log.Fatal("got an invalid router request which is not HTTP")
	}
	if ca.AuthCallback == nil {
		log.Fatal("no auth callback defined")
	}
	if ca.AuthCallback(httpctx.Request, rr.Message.(*BlindCA)) {
		msg.OK = true
		msg.SignerR = ca.NewRequestKey()
	} else {
		msg.SetError("unauthorized")
	}
	if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
		log.Warn(err)
	}
}

// Signature is the performing signature handler.
// If the R point is valid and exist in cache, will perform a blind signature over the Hash
func (ca *BlindCA) Signature(rr router.RouterRequest) {
	var err error
	msg := &BlindCA{}
	req := rr.Message.(*BlindCA)
	if len(req.MessageHash) == 0 {
		msg.SetError("messageHash is empty")
		if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
			log.Warn(err)
		}
		return
	}
	if req.SignerR == nil {
		msg.SetError("signerR is empty")
		if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
			log.Warn(err)
		}
		return
	}
	msg.BlindSignature, err = ca.Sign(req.SignerR, req.MessageHash)
	if err != nil {
		msg.SetError(err.Error())
		if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
			log.Warn(err)
		}
		return
	}
	msg.OK = true
	if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
		log.Warn(err)
	}
}
