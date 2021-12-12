#include <core.p4>
#include <v1model.p4>

/************************************************************************
************************** Defines **************************************
*************************************************************************/

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86dd
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17
#define IP_PROTO_SRV6 8w43
#define IP_VERSION_4 4w4

#define SRV6_MAX_HOPS 6

typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<9>   port_t;

const port_t CPU_PORT = 255;



/************************************************************************
************************** Headers **************************************
*************************************************************************/

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header srv6_header_t {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> segment_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

header srv6_segment_list_t{
    bit<128> sid;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}

/************************************************************************
*********************** Custom Headers  *********************************
*************************************************************************/

struct headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    srv6_header_t srh;
    srv6_segment_list_t[SRV6_MAX_HOPS] segment_list;
    tcp_t tcp;
    udp_t udp;
}

struct local_metadata_t {
    bit<16>        l4_src_port;
    bit<16>        l4_dst_port;
    ipv6_addr_t next_sid;
    bit<8>         ip_proto;
}


/************************************************************************
**************************** Parser *************************************
*************************************************************************/

parser parser_impl(packet_in packet,
                  out headers_t hdr,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            ETH_TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_SRV6: parse_srv6;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_srv6 {
        packet.extract(hdr.srh);
        transition parse_segment_list;
    }

    state parse_segment_list {
        packet.extract(hdr.segment_list.next);
        bool next_sid = (bit<32>)hdr.srh.segment_left - 1 == (bit<32>)hdr.segment_list.lastIndex;
        transition select(next_sid){
            true: mark_next_sid;
            default: check_last_sid;
        }
    }

    state mark_next_sid{
        local_metadata.next_sid = hdr.segment_list.last.sid;
        transition check_last_sid;
    }

    state check_last_sid {
        bool last_sid = (bit<32>)hdr.srh.last_entry == (bit<32>)hdr.segment_list.lastIndex;
        transition select(last_sid){
            true: parse_srv6_next_hdr;
            false: parse_segment_list;
        }
    }

    state parse_srv6_next_hdr{
        transition select(hdr.srh.next_hdr){
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }
}


/************************************************************************
*********************** Verify Checksum *********************************
*************************************************************************/

control verify_checksum_control(inout headers_t hdr,
                                inout local_metadata_t local_metadata) {
    apply {
        // Assume checksum is always correct.
    }
}


/************************************************************************
*********************** Ingress Pipeline*********************************
*************************************************************************/

control ingress(inout headers_t hdr,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {


    action drop(){
    	mark_to_drop(standard_metadata);
    }

    table local_mac_table {

    	key = {
    		hdr.ethernet.dst_addr: exact;
    	}
    	actions = {
    		NoAction;
    	}
    }


    action set_next_hop(mac_addr_t dmac, port_t port){
    	hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
    	hdr.ethernet.dst_addr = dmac;
    	hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    	standard_metadata.egress_spec = port;
    }

    table routing_v6_table {
    	key = {
    		hdr.ipv6.dst_addr: lpm;
    	}
    	actions = {
    		set_next_hop;
    	}
    }


    action end(){
        hdr.srh.segment_left = hdr.srh.segment_left - 1;
        hdr.ipv6.dst_addr = local_metadata.next_sid;
    }

    table local_sid_table {
    	key = {
    		hdr.ipv6.dst_addr: lpm;
    	}
    	actions = {
    		end;
    	}

    }

    action insert_srh(bit<8> num_segments){
        hdr.srh.setValid();
        hdr.srh.next_hdr = hdr.ipv6.next_hdr;
        hdr.srh.hdr_ext_len = num_segments * 2;
        hdr.srh.routing_type = 4;
        hdr.srh.segment_left = num_segments - 1;
        hdr.srh.last_entry = num_segments - 1;
        hdr.srh.flags = 0;
        hdr.srh.tag = 0;
        hdr.ipv6.next_hdr = IP_PROTO_SRV6;
    }

    action insert_segment_list_2(ipv6_addr_t s1, ipv6_addr_t s2){
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40;
        insert_srh(2);
        hdr.segment_list[0].setValid();
        hdr.segment_list[0].sid = s2;
        hdr.segment_list[1].setValid();
        hdr.segment_list[1].sid = s1;
    }

    action insert_segment_list_3(ipv6_addr_t s1, ipv6_addr_t s2, ipv6_addr_t s3){
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 56;
        insert_srh(3);
        hdr.segment_list[0].setValid();
        hdr.segment_list[0].sid = s3;
        hdr.segment_list[1].setValid();
        hdr.segment_list[1].sid = s2;
        hdr.segment_list[2].setValid();
        hdr.segment_list[2].sid = s1;
    }

    table transit_table{
    	key={
    		hdr.ipv6.dst_addr: lpm;
    	}
    	actions = {
    		insert_segment_list_2;
    		insert_segment_list_3;
    	}
    }

    action srv6_pop(){
        hdr.ipv6.next_hdr = hdr.srh.next_hdr;
        bit<16> srh_size = (((bit<16>)hdr.srh.last_entry + 1) << 4) + 8;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len - srh_size;

        hdr.srh.setInvalid();
        hdr.segment_list[0].setInvalid();
        hdr.segment_list[1].setInvalid();
        hdr.segment_list[2].setInvalid();
        hdr.segment_list[3].setInvalid();
        hdr.segment_list[4].setInvalid();
        hdr.segment_list[5].setInvalid();
    }



    apply {
        
        
        if (standard_metadata.ingress_port == CPU_PORT) {
        	// Receive packets from controller, namely packet_out message.
        	// Directly tell switch where the port packets sent to.

        	standard_metadata.egress_spec = hdr.packet_out.egress_port;

        	// pop the header of packet-out packet

        	hdr.packet_out.setInvalid();
        	exit;
        }


        // The logic of how to handle srv6 header
        // simple version, only considering ipv6 packets and srv6 packets

    	if(local_mac_table.apply().hit){
    		if(hdr.ipv6.isValid()){
    			if(local_sid_table.apply().hit){
    				if(hdr.srh.isValid() && hdr.srh.segment_left == 0){
    					srv6_pop();
    				}
    			}else{
    				transit_table.apply();
    			}

    			routing_v6_table.apply();

    			if(hdr.ipv6.hop_limit == 0){
    				drop();
    			}
    		}

    	}

     }
}





/************************************************************************
*********************** Egress Pipeline**********************************
*************************************************************************/


control egress(inout headers_t hdr,
               inout local_metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {

    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
        	// Handle packet-in packet, if egress_port is cpu port, which means this packet is sent to controller
            // Add the packet-in header

            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;

        }    
    }
}



/************************************************************************
*********************** Compute Checksum ********************************
*************************************************************************/

control compute_checksum_control(inout headers_t hdr,
                                 inout local_metadata_t local_metadata) {
    apply {
        update_checksum(hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}


/************************************************************************
**************************** Deparser ***********************************
*************************************************************************/

control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srh);
        packet.emit(hdr.segment_list);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}


/************************************************************************
**************************** Switch *************************************
*************************************************************************/

V1Switch(parser_impl(),
         verify_checksum_control(),
         ingress(),
         egress(),
         compute_checksum_control(),
         deparser()) main;







































































































































































































