package blindca

import (
	"github.com/vocdoni/multirpc/router"
	"github.com/vocdoni/multirpc/transports/mhttp"
	"go.vocdoni.io/dvote/log"
)

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

func (ca *BlindCA) Signature(rr router.RouterRequest) {
	var err error
	msg := &BlindCA{}
	req := rr.Message.(*BlindCA)
	if len(req.MessageHash) == 0 {
		msg.SetError("messageHash is empty")
		rr.Send(router.BuildReply(msg, rr))
		return
	}
	if req.SignerR == nil {
		msg.SetError("signerR is empty")
		rr.Send(router.BuildReply(msg, rr))
		return
	}

	msg.BlindSignature, err = ca.Sign(req.SignerR, req.MessageHash)
	if err != nil {
		msg.SetError(err.Error())
		rr.Send(router.BuildReply(msg, rr))
		return
	}
	msg.OK = true
	if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
		log.Warn(err)
	}
}
