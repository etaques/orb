package orbreceiver

import (
	"fmt"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"os"
	"reflect"
	"testing"
)

func generateMetricsRequest() pmetricotlp.Request {
	md := pmetric.NewMetrics()
	m := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	m.SetName("test_metric")
	m.Gauge().DataPoints().AppendEmpty().SetIntVal(123)
	return pmetricotlp.NewRequestFromMetrics(md)
}

func Test_jsonEncoder_unmarshalMetricsRequest(t *testing.T) {

	type args struct {
		metric pmetricotlp.Request
	}
	tests := []struct {
		name        string
		args        args
		want        pmetricotlp.Request
		wantErr     bool
		byteExample string
	}{
		{
			name: "going back and forth",
			args: args{
				metric: generateMetricsRequest(),
			},
			want:        generateMetricsRequest(),
			wantErr:     false,
			byteExample: "\n�p\n�\u0001\n5\n\fservice.name\u0012%\n#pktvisor_prometheus/localhost:10853\n(\n\u0013service.instance.id\u0012\u0011\n\u000Flocalhost:10853\n\u0018\n\nnet.host.port\u0012\a\n\u000510853\n\u0015\n\vhttp.scheme\u0012\u0006\n\u0004http\u0012�n\n\u0000\u0012�\u0001\n\vpackets_out\u0012\u001DCount of total egress packets*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000 |@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\v\n\u0010packets_top_ipv4\u0012\u0015Top IPv4 IP addresses*�\n\nl\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000��@:\u0016\n\u0004ipv4\u0012\u000E\n\f192.168.0.13:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nl\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000Z�@:\u0016\n\u0004ipv4\u0012\u000E\n\f192.168.0.15:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\ng\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�^@:\u0011\n\u0004ipv4\u0012\t\n\a1.1.1.2:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nn\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�Z@:\u0018\n\u0004ipv4\u0012\u0010\n\u000E35.186.227.140:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nk\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000X@:\u0015\n\u0004ipv4\u0012\n\v52.40.138.9:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\ng\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�I@:\u0011\n\u0004ipv4\u0012\t\n\a8.8.8.8:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nn\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000D@:\u0018\n\u0004ipv4\u0012\u0010\n\u000E34.120.117.234:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nk\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000B@:\u0015\n\u0004ipv4\u0012\n\v52.85.213.3:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nk\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�@@:\u0015\n\u0004ipv4\u0012\n\v52.97.11.82:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nl\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�@@:\u0016\n\u0004ipv4\u0012\u000E\n\f35.161.134.0:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nd\u0019@u�\n�]\u0015\u0017:\u0015\n\u0004ipv4\u0012\n\v52.35.17.16:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard@\u0001\nh\u0019@u�\n�]\u0015\u0017:\u0019\n\u0004ipv4\u0012\u0011\n\u000F239.255.255.250:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard@\u0001\nf\u0019@u�\n�]\u0015\u0017:\u0017\n\u0004ipv4\u0012\u000F\n\n35.162.19.172:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard@\u0001\u0012�\u0001\n\u001Ddns_wire_packets_deep_samples\u0012<Total DNS wire packets that were sampled for deep inspection*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�d@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0018dns_wire_packets_queries\u0012<Total DNS wire packets flagged as query (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�P@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0018dns_wire_packets_srvfail\u0012UTotal DNS wire packets flagged as reply with return code SRVFAIL (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\b\n\u0015dns_xact_out_top_slow\u0012\\Top QNAMES in transactions where host is the client and transaction speed is slower than p90*�\a\n~\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0010@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:(\n\u0005qname\u0012\u001F\n\u001Dlocation.services.mozilla.com\nx\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\"\n\u0005qname\u0012\u0019\n\u0017youtube-ui.l.google.com\nu\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u001F\n\u0005qname\u0012\u0016\n\u0014training.knowbe4.com\n�\u0001\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:1\n\u0005qname\u0012(\n&locprod2-elb-us-west-2.prod.mozaws.net\n}\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000�?:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:'\n\u0005qname\u0012\u001E\n\u001Cprofile.accounts.firefox.com\n~\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000�?:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:(\n\u0005qname\u0012\u001F\n\u001Dconnectivity-check.ubuntu.com\n�\u0001\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000�?:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:6\n\u0005qname\u0012-\n+sync-1-us-west1-g.sync.services.mozilla.com\u0012�\u0001\n\u0014packets_deep_samples\u00123Total packets that were sampled for deep inspection*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000���@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012{\n\vpackets_udp\u0012\u0014Count of UDP packets*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000i@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u001Fpackets_cardinality_dst_ips_out\u0012\u001ADestination IP cardinality*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000>@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0002\n\ndns_top_qtype\u0012\u000FTop query types*�\u0002\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�U@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0005qtype\u0012\u0006\n\u0004AAAA\nb\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�R@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\f\n\u0005qtype\u0012\u0003\n\u0001A\nd\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000E\n\u0005qtype\u0012\u0005\n\u0003PTR\u0012�\u0001\n\u0015dns_wire_packets_ipv4\u0012>Total DNS wire packets received over IPv4 (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@d@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0015dns_wire_packets_ipv6\u0012>Total DNS wire packets received over IPv6 (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0018dns_wire_packets_noerror\u0012UTotal DNS wire packets flagged as reply with return code NOERROR (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@X@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0010\n\u0011dns_top_udp_ports\u00126Top UDP source port on the query side of a transaction*�\u000F\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000535791\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000535330\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000541982\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000553907\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000539402\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000533434\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000544855\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000546322\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000542076\ne\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000559762\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000555494@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000550579@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000548855@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000545312@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000556600@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000541354@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000552551@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000558743@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000541483@\u0001\n^\u0019@u�\n�]\u0015\u0017:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u000F\n\u0004port\u0012\a\n\u000547117@\u0001\u0012�\u0006\n\u000Edns_top_qname2\u0012/Top QNAMES, aggregated at a depth of two labels*�\u0006\nm\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@S@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0017\n\u0005qname\u0012\u000E\n\f.mozilla.com\nl\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000K@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0016\n\u0005qname\u0012\n\v.mozaws.net\nm\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000$@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0017\n\u0005qname\u0012\u000E\n\f.firefox.com\nm\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000$@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0017\n\u0005qname\u0012\u000E\n\f.knowbe4.com\nl\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0018@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0016\n\u0005qname\u0012\n\v.google.com\nl\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0010@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0016\n\u0005qname\u0012\n\v.ubuntu.com\nl\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0016\n\u0005qname\u0012\n\v._tcp.local\u0012�\u0001\n\u0015dns_cardinality_qname\u00125Cardinality of unique QNAMES, both ingress and egress*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000 @:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0010packets_other_l4\u0012)Count of packets which are not UDP or TCP*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u00002@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012P\n\u0017scrape_duration_seconds\u0012\u0016Duration of the scrape\u001A\aseconds*\u0014\n\u0012\u0019@u�\n�]\u0015\u0017!�A\u001C͌܁?\u0012�\u0001\n\u0014dns_wire_packets_tcp\u0012=Total DNS wire packets received over TCP (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0019dns_xact_counts_timed_out\u0012/Total number of DNS transactions that timed out*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0012dns_xact_out_total\u0012.Total egress DNS transactions (host is client)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000P@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012{\n\vpackets_tcp\u0012\u0014Count of TCP packets*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000�D�@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0006\n\u0010packets_top_ipv6\u0012\u0015Top IPv6 IP addresses*�\u0006\n}\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000B@:'\n\u0004ipv6\u0012\u001F\n\u001D2a01:111:f100:3001::8987:1339:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\ns\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u00004@:\u001D\n\u0004ipv6\u0012\u0015\n\u00132606:4700::6812:d21:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nh\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0018@:\u0012\n\u0004ipv6\u0012\n\n\bff02::16:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\ng\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000@:\u0011\n\u0004ipv6\u0012\t\n\aff02::1:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nh\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000@:\u0012\n\u0004ipv6\u0012\n\n\bff02::fb:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\nr\u0019@u�\n�]\u0015\u0017:#\n\u0004ipv6\u0012\u001B\n\u0019fe80::8601:12ff:fe61:31aa:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard@\u0001\nk\u0019@u�\n�]\u0015\u0017:\u001C\n\u0004ipv6\u0012\u0014\n\u00122600:1901:0:38d7:::%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard@\u0001\u0012�\u0001\n\u0016dns_wire_packets_total\u0012\u0016Total DNS wire packets*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�d@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0015dns_xact_counts_total\u0012*Total DNS transactions (query/reply pairs)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000P@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0002\n\u0019dns_xact_out_quantiles_us\u0012XQuantiles of transaction timing (query/reply pairs) when host is client, in microsecondsZ�\u0001\n�\u0001\u0011@\u0013�c\u0004]\u0015\u0017\u0019@u�\n�]\u0015\u0017!@\u0000\u0000\u0000\u0000\u0000\u0000\u0000)\u0000\u0000\u0000\u0000pr�@2\u0012\t\u0000\u0000\u0000\u0000\u0000\u0000�?\u0011\u0000\u0000\u0000\u0000\u0000u�@2\u0012\t�������?\u0011\u0000\u0000\u0000\u0000�\u0004�@2\u0012\tffffff�?\u0011\u0000\u0000\u0000\u0000@��@2\u0012\t�G�z\u0014��?\u0011\u0000\u0000\u0000\u0000pr�@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u00127\n\u0002up\u0012\u001BThe scraping was successful*\u0014\n\u0012\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000�?\u0012�\u0001\n%scrape_samples_post_metric_relabeling\u0012CThe number of samples remaining after metric relabeling was applied*\u0014\n\u0012\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@[@\u0012`\n\u0013scrape_series_added\u00123The approximate number of new series in this scrape*\u0014\n\u0012\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@[@\u0012�\u0001\n\u0018dns_wire_packets_replies\u0012<Total DNS wire packets flagged as reply (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@X@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0019dns_wire_packets_filtered\u0012PTotal DNS wire packets seen that did not match the configured filter(s) (if any)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\a\n\u000Edns_top_qname3\u00121Top QNAMES, aggregated at a depth of three labels*�\u0006\nv\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@S@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard: \n\u0005qname\u0012\u0017\n\u0015.services.mozilla.com\nq\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000K@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u001B\n\u0005qname\u0012\u0012\n\u0010.prod.mozaws.net\nu\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000$@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u001F\n\u0005qname\u0012\u0016\n\u0014training.knowbe4.com\nv\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000$@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard: \n\u0005qname\u0012\u0017\n\u0015.accounts.firefox.com\nn\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0018@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0018\n\u0005qname\u0012\u000F\n\n.l.google.com\n~\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0010@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:(\n\u0005qname\u0012\u001F\n\u001Dconnectivity-check.ubuntu.com\n|\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\b@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:&\n\u0005qname\u0012\u001D\n\u001B_spotify-connect._tcp.local\u0012�\u0001\n\u0015packets_rates_pps_out\u0012$Rate of egress in packets per secondZ�\u0001\n�\u0001\u0011@\u0013�c\u0004]\u0015\u0017\u0019@u�\n�]\u0015\u0017!<\u0000\u0000\u0000\u0000\u0000\u0000\u0000)\u0000\u0000\u0000\u0000\u0000�F@2\u0012\t\u0000\u0000\u0000\u0000\u0000\u0000�?\u0011\u0000\u0000\u0000\u0000\u0000\u0000\u0010@2\u0012\t�������?\u0011\u0000\u0000\u0000\u0000\u0000\u00007@2\u0012\tffffff�?\u0011\u0000\u0000\u0000\u0000\u0000�@@2\u0012\t�G�z\u0014��?\u0011\u0000\u0000\u0000\u0000\u0000�F@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0002\n\u0017packets_rates_pps_total\u0012GRate of all packets (combined ingress and egress) in packets per secondZ�\u0001\n�\u0001\u0011@\u0013�c\u0004]\u0015\u0017\u0019@u�\n�]\u0015\u0017!<\u0000\u0000\u0000\u0000\u0000\u0000\u0000)\u0000\u0000\u0000\u0000\u0000\b�@2\u0012\t\u0000\u0000\u0000\u0000\u0000\u0000�?\u0011\u0000\u0000\u0000\u0000\u0000@W@2\u0012\t�������?\u0011\u0000\u0000\u0000\u0000\u0000px@2\u0012\tffffff�?\u0011\u0000\u0000\u0000\u0000\u0000��@2\u0012\t�G�z\u0014��?\u0011\u0000\u0000\u0000\u0000\u0000\b�@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\ndns_top_rcode\u0012\u0010Top result codes*j\nh\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@X@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard:\u0012\n\u0005rcode\u0012\t\n\aNOERROR\u0012�\u0001\n\u0014packets_rates_pps_in\u0012%Rate of ingress in packets per secondZ�\u0001\n�\u0001\u0011@\u0013�c\u0004]\u0015\u0017\u0019@u�\n�]\u0015\u0017!<\u0000\u0000\u0000\u0000\u0000\u0000\u0000)\u0000\u0000\u0000\u0000\u0000\u0000�@2\u0012\t\u0000\u0000\u0000\u0000\u0000\u0000�?\u0011\u0000\u0000\u0000\u0000\u0000\u0000V@2\u0012\t�������?\u0011\u0000\u0000\u0000\u0000\u00000x@2\u0012\tffffff�?\u0011\u0000\u0000\u0000\u0000\u0000��@2\u0012\t�G�z\u0014��?\u0011\u0000\u0000\u0000\u0000\u0000\u0000�@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\npackets_total\u0012\u0017Total packets processed*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000���@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0002\n\u000Fdns_rates_total\u0012ERate of all DNS wire packets (combined ingress and egress) per secondZ�\u0001\n�\u0001\u0011@\u0013�c\u0004]\u0015\u0017\u0019@u�\n�]\u0015\u0017!;\u0000\u0000\u0000\u0000\u0000\u0000\u0000)\u0000\u0000\u0000\u0000\u0000\u0000A@2\t\t\u0000\u0000\u0000\u0000\u0000\u0000�?2\u0012\t�������?\u0011\u0000\u0000\u0000\u0000\u0000\u0000,@2\u0012\tffffff�?\u0011\u0000\u0000\u0000\u0000\u0000\u00002@2\u0012\t�G�z\u0014��?\u0011\u0000\u0000\u0000\u0000\u0000\u0000A@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0014dns_wire_packets_udp\u0012=Total DNS wire packets received over UDP (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�d@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0019dns_wire_packets_nxdomain\u0012VTotal DNS wire packets flagged as reply with return code NXDOMAIN (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0018dns_wire_packets_refused\u0012UTotal DNS wire packets flagged as reply with return code REFUSED (ingress and egress)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u0011dns_xact_in_total\u0012/Total ingress DNS transactions (host is server)*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_dns:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012}\n\fpackets_ipv4\u0012\u0015Count of IPv4 packets*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000���@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012}\n\fpackets_ipv6\u0012\u0015Count of IPv6 packets*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000�P@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\npackets_in\u0012\u001ECount of total ingress packets*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000���@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012�\u0001\n\u001Epackets_cardinality_src_ips_in\u0012\u0015Source IP cardinality*V\nT\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000\u00009@:%\n\u0006module\u0012\u001B\n\u0019otel-standard-default_net:\u0019\n\u0006policy\u0012\u000F\n\notel-standard\u0012X\n\u0016scrape_samples_scraped\u0012(The number of samples the target exposed*\u0014\n\u0012\u0019@u�\n�]\u0015\u0017!\u0000\u0000\u0000\u0000\u0000@[@",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodingBuf, err := tt.args.metric.MarshalProto()
			if (err != nil) != tt.wantErr {
				t.Errorf("unmarshalMetricsRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			e := protoEncoder{}
			got, err := e.unmarshalMetricsRequest(encodingBuf)
			if (err != nil) != tt.wantErr {
				t.Errorf("unmarshalMetricsRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmarshalMetricsRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeTestDataFiles(t *testing.T) {
	dir := "/home/lpegoraro/workspace/orb/sinker/otel/orbreceiver/testdata"
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, dirEntry := range files {
		fileName := fmt.Sprintf("%s/%s", dir, dirEntry.Name())
		file, err := os.ReadFile(fileName)
		if err != nil {
			t.Fatal(err)
		}
		e := protoEncoder{}
		got, err := e.unmarshalMetricsRequest(file)
		if err != nil {
			t.Errorf("unmarshalMetricsRequest() error = %v", err)
			return
		}
		//md := req.Metrics()
		//dataPointCount := md.DataPointCount()
		//if dataPointCount == 0 {
		//	return pmetricotlp.NewResponse(), nil
		//}
		//
		//ctx = r.obsrecv.StartMetricsOp(ctx)
		//err := r.nextConsumer.ConsumeMetrics(ctx, md)
		//r.obsrecv.EndMetricsOp(ctx, dataFormatProtobuf, dataPointCount, err)

		t.Log("succeeded reading and unmarshalling got: ", got, string(file))
	}
}
