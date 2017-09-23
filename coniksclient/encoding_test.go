package coniksclient

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/coniks-sys/coniks-go/coniksserver"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

func TestUnmarshalErrorResponse(t *testing.T) {
	errResponse := protocol.NewErrorResponse(protocol.ErrMalformedClientMessage)
	msg, err := json.Marshal(errResponse)
	if err != nil {
		t.Fatal(err)
	}
	res := UnmarshalResponse(protocol.RegistrationType, msg)
	if res.Error != protocol.ErrMalformedClientMessage {
		t.Error("Expect error", protocol.ErrMalformedClientMessage,
			"got", res.Error)
	}
}

func TestUnmarshalMalformedErrorResponse(t *testing.T) {
	errResponse := protocol.NewErrorResponse(protocol.ReqNameNotFound)
	msg, err := json.Marshal(errResponse)
	if err != nil {
		t.Fatal(err)
	}
	res := UnmarshalResponse(protocol.RegistrationType, msg)
	if res.Error != protocol.ErrMalformedDirectoryMessage {
		t.Error("Expect error", protocol.ErrMalformedDirectoryMessage,
			"got", res.Error)
	}
}

func TestUnmarshalSampleMessage(t *testing.T) {
	d, _ := directory.NewTestDirectory(t, true)
	res, _ := d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	msg, _ := coniksserver.MarshalResponse(res)
	response := UnmarshalResponse(protocol.RegistrationType, []byte(msg))
	str := response.DirectoryResponse.(*protocol.DirectoryProof).STR[0]
	if !bytes.Equal(d.LatestSTR().Serialize(), str.Serialize()) {
		t.Error("Cannot unmarshal Associate Data properly")
	}
}
