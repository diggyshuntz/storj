// Copyright (C) 2018 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"crypto"
	"crypto/ecdsa"

	"github.com/gogo/protobuf/proto"
	"github.com/gtank/cryptopasta"
	"github.com/zeebo/errs"
)

var (
	//ErrECDSA indicates a key was not an ECDSA key
	ErrECDSA = errs.New("Key is not ecdsa key")
	//ErrSign indicates a failure during signing
	ErrSign = errs.Class("Failed to sign message")
	//ErrVerify indicates a failure during signature validation
	ErrVerify = errs.Class("Failed to validate message signature")
	//ErrSigLen indicates an invalid signature length
	ErrSigLen = errs.Class("Invalid signature length")
	//ErrSerial indicates an invalid serial number length
	ErrSerial = errs.Class("Invalid SerialNumber")
	//ErrExpired indicates the agreement is expired
	ErrExpired = errs.Class("Agreement is expired")
	//ErrSigner indicates a public key / node id mismatch
	ErrSigner = errs.Class("Message public key did not match expected signer")
	//ErrBadID indicates a public key / node id mismatch
	ErrBadID = errs.Class("Node ID did not match expected id")
	//ErrMarshal indicates a failure during serialization
	ErrMarshal = errs.Class("Could not marshal item to bytes")
	//ErrUnmarshal indicates a failure during deserialization
	ErrUnmarshal = errs.Class("Could not unmarshal bytes to item")
	//ErrMissing indicates missing or empty information
	ErrMissing = errs.Class("Required field is empty")
)

//SignableMessage is a protocol buffer with a certs and a signature
//Note that we assume proto.Message is a pointer receiver
type SignableMessage interface {
	proto.Message
	GetSignature() []byte
	SetSignature([]byte)
	Marshal() ([]byte, error)
}

//SignMessage adds the crypto-related aspects of signed message
func SignMessage(msg SignableMessage, key crypto.PrivateKey) error {
	if msg == nil {
		return ErrMissing.New("message")
	} else if key == nil {
		return ErrMissing.New("private key")
	}
	msg.SetSignature(nil)
	msgBytes, err := msg.Marshal()
	if err != nil {
		return ErrMarshal.Wrap(err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return ErrECDSA
	}
	signature, err := cryptopasta.Sign(msgBytes, ecdsaKey)
	if err != nil {
		return ErrSign.Wrap(err)
	}
	msg.SetSignature(signature)
	return nil
}

//VerifyMessage checks the crypto-related aspects of signed message
func VerifyMessage(msg SignableMessage, key crypto.PublicKey) error {
	if msg == nil {
		return ErrMissing.New("message")
	} else if msg.GetSignature() == nil {
		return ErrMissing.New("message signature")
	} else if key == nil {
		return ErrMissing.New("public key")
	}
	signature := msg.GetSignature()
	msg.SetSignature(nil)
	defer msg.SetSignature(signature)
	msgBytes, err := msg.Marshal()
	if err != nil {
		return ErrMarshal.Wrap(err)
	}
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrECDSA
	}
	signatureLength := ecdsaKey.Curve.Params().P.BitLen() / 8
	if len(signature) < signatureLength {
		return ErrSigLen.New("%d vs %d", len(signature), signatureLength)
	}
	if ok := cryptopasta.Verify(msgBytes, signature, ecdsaKey); !ok {
		return ErrVerify.New("%+v", ok)
	}
	return nil
}
