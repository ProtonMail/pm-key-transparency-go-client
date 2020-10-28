package ktclient

import (
	"testing"
)

func TestProof(t *testing.T) {
	tgt := "bb27df338e530c4af0f46bf35a3a1adbd9547f01791a6b9d3e9dda0eb10ed156"
	key := "8183f09c4ba510abdc6c1cb4ecbc1a114d0045c7fca8da28a2858a2a0b8f3fae"
	val := "1afa5343a3ebabecf9498717ed5bcd1d931a65502e31"

	node := &Node{[]byte(key), []byte(val)}

	neighbours := map[uint8][]byte{
		0: []byte("2084890f1868ece83ec2cf2ce9a7753d84d20aba0e5444f885ca1b532b2e251f"),
		1: []byte("89a07695a54a30e567e4cb70df7ab19a95efb9c93d450f2b25f27610a648a328"),
		2: []byte("acb1c6bac4b4d8ba10bad857f360a982705e1f24b42ac93e90f1c81297d91891"),
		4: []byte("f15f5b01892d92ff98fbc62988620487e9c58ec8e12c97d85f766f0802919ed3"),
		6: []byte("e4bad8857543513ca80fd8243125049efc37114376f705d9a4e29a75ade15e49"),
	}
	println(node.VerifyProof([]byte(tgt), neighbours))
}
