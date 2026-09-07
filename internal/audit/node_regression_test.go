package audit

import "testing"

func TestNodeCorrelationIsolated(t *testing.T) {
	for _, order := range [][]string{{"a", "b"}, {"b", "a"}} {
		a := NewAssembler(0)
		for _, node := range order {
			a.Add(mustParseRecord(t, `node=`+node+` type=SYSCALL msg=audit(100.1:1): pid=1`))
		}
		for _, node := range []string{"a", "b"} {
			events := a.Add(mustParseRecord(t, `node="`+node+`" type=EOE msg=audit(100.1:1):`))
			if len(events) != 1 || len(events[0].Records) != 2 || events[0].Records[0].Node != node {
				t.Fatalf("merged nodes: %#v", events)
			}
			e := BuildCanonicalEvent(events[0], CanonicalOptions{})
			if e.Source == nil || e.Source.Host != node {
				t.Fatal("lost node")
			}
		}
	}
}
func TestMixedNodePresenceNeverMerges(t *testing.T) {
	for _, order := range [][]string{{"node=a ", ""}, {"", "node=a "}} {
		a := NewAssembler(0)
		for _, prefix := range order {
			a.Add(mustParseRecord(t, prefix+`type=SYSCALL msg=audit(100.1:1): pid=1`))
		}
		events := a.FlushAll()
		if len(events) != 2 {
			t.Fatalf("merged nodes: %#v", events)
		}
		for _, event := range events {
			if !event.MixedNode || len(event.Records) != 1 {
				t.Fatalf("missing ambiguity: %#v", event)
			}
		}
	}
}
