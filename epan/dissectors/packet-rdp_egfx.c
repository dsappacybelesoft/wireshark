/* Packet-rdp_egfx.c
 * Routines for the EGFX RDP channel
 * Copyright 2021, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See: "[MS-RDPEGFX] "
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/tvbuff_rdp.h>
#include <epan/crc32-tvb.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"

void proto_register_rdp_egfx(void);
void proto_reg_handoff_rdp_egfx(void);

static int proto_rdp_egfx;

static int hf_egfx_cmdId;
static int hf_egfx_flags;
static int hf_egfx_pduLength;

static int hf_egfx_caps_capsSetCount;
static int hf_egfx_cap_version;
static int hf_egfx_cap_length;

static int hf_egfx_reset_width;
static int hf_egfx_reset_height;
static int hf_egfx_reset_monitorCount;
static int hf_egfx_reset_monitorDefLeft;
static int hf_egfx_reset_monitorDefTop;
static int hf_egfx_reset_monitorDefRight;
static int hf_egfx_reset_monitorDefBottom;
static int hf_egfx_reset_monitorDefFlags;

static int hf_egfx_w2s1_surface_id;
static int hf_egfx_w2s1_codec_id;
static int hf_egfx_w2s1_pixel_format;
static int hf_egfx_w2s1_dest_rectLeft;
static int hf_egfx_w2s1_dest_rectTop;
static int hf_egfx_w2s1_dest_rectRight;
static int hf_egfx_w2s1_dest_rectBottom;
static int hf_egfx_w2s1_bitmap_data_size;
static int hf_egfx_w2s1_bitmap_data_planar_header_cll;
static int hf_egfx_w2s1_bitmap_data_planar_header_cs;
static int hf_egfx_w2s1_bitmap_data_planar_header_rle;
static int hf_egfx_w2s1_bitmap_data_planar_header_na;
static int hf_egfx_w2s1_bitmap_data_clear_flag_glyph_index;
static int hf_egfx_w2s1_bitmap_data_clear_flag_glyph_hit;
static int hf_egfx_w2s1_bitmap_data_clear_flag_cache_reset;
static int hf_egfx_w2s1_bitmap_data_clear_seq_num;
static int hf_egfx_w2s1_bitmap_data_clear_glyph_index;
static int hf_egfx_w2s1_bitmap_data_clear_composite_payload;

static int hf_egfx_w2s2_surface_id;
static int hf_egfx_w2s2_codec_id;
static int hf_egfx_w2s2_codec_context_id;
static int hf_egfx_w2s2_pixel_format;
static int hf_egfx_w2s2_bitmap_data_size;
static int hf_egfx_w2s2_progressive_block_type;
static int hf_egfx_w2s2_progressive_block_len;
static int hf_egfx_w2s2_progressive_sync_magic;
static int hf_egfx_w2s2_progressive_sync_version;
static int hf_egfx_w2s2_progressive_frame_index;
static int hf_egfx_w2s2_progressive_frame_reg_count;
static int hf_egfx_w2s2_progressive_ctx_context_id;
static int hf_egfx_w2s2_progressive_ctx_tile_size;
static int hf_egfx_w2s2_progressive_ctx_flags;
static int hf_egfx_w2s2_progressive_region_tile_size;
static int hf_egfx_w2s2_progressive_region_num_rects;
static int hf_egfx_w2s2_progressive_region_num_quant;
static int hf_egfx_w2s2_progressive_region_num_prog_quant;
static int hf_egfx_w2s2_progressive_region_flags;
static int hf_egfx_w2s2_progressive_region_num_tiles;
static int hf_egfx_w2s2_progressive_region_tiles_data_size;
static int hf_egfx_w2s2_progressive_region_rect_x;
static int hf_egfx_w2s2_progressive_region_rect_y;
static int hf_egfx_w2s2_progressive_region_rect_width;
static int hf_egfx_w2s2_progressive_region_rect_height;
static int hf_egfx_w2s2_progressive_region_tile_ydata;
static int hf_egfx_w2s2_progressive_region_tile_cbdata;
static int hf_egfx_w2s2_progressive_region_tile_crdata;
static int hf_egfx_w2s2_progressive_region_tile_data;

static int hf_egfx_ack_queue_depth;
static int hf_egfx_ack_frame_id;
static int hf_egfx_ack_total_decoded;
static int hf_egfx_ack_frame_start;
static int hf_egfx_ack_frame_end;

static int hf_egfx_ackqoe_frame_id;
static int hf_egfx_ackqoe_timestamp;
static int hf_egfx_ackqoe_timediffse;
static int hf_egfx_ackqoe_timediffedr;
static int hf_egfx_ackqoe_frame_start;
static int hf_egfx_ackqoe_frame_end;

static int hf_egfx_start_timestamp;
static int hf_egfx_start_frameid;
static int hf_egfx_start_acked_in;

static int hf_egfx_end_frameid;
static int hf_egfx_end_acked_in;


static int ett_rdp_egfx;
static int ett_egfx_caps;
static int ett_egfx_capsconfirm;
static int ett_egfx_cap;
static int ett_egfx_cap_version;
static int ett_egfx_ack;
static int ett_egfx_ackqoe;
static int ett_egfx_reset;
static int ett_egfx_monitors;
static int ett_egfx_monitordef;
static int ett_egfx_w2s1;
static int ett_egfx_w2s1_rect;
static int ett_egfx_w2s1_bitmap;
static int ett_egfx_w2s1_composite_payload;
static int ett_egfx_w2s2;
static int ett_egfx_w2s2_bitmap;
static int ett_egfx_w2s2_block;
static int ett_egfx_w2s2_region_rects;
static int ett_egfx_w2s2_region_quants;
static int ett_egfx_w2s2_region_prog_quants;
static int ett_egfx_w2s2_region_tiles;


static expert_field ei_egfx_pdulen_invalid;
static expert_field ei_egfx_invalid_compression;


#define PNAME  "RDP Graphic pipeline channel Protocol"
#define PSNAME "EGFX"
#define PFNAME "rdp_egfx"

enum {
	RDPGFX_CMDID_WIRETOSURFACE_1 		= 0x0001,
	RDPGFX_CMDID_WIRETOSURFACE_2 		= 0x0002,
	RDPGFX_CMDID_DELETEENCODINGCONTEXT 	= 0x0003,
	RDPGFX_CMDID_SOLIDFILL 				= 0x0004,
	RDPGFX_CMDID_SURFACETOSURFACE 		= 0x0005,
	RDPGFX_CMDID_SURFACETOCACHE 		= 0x0006,
	RDPGFX_CMDID_CACHETOSURFACE 		= 0x0007,
	RDPGFX_CMDID_EVICTCACHEENTRY 		= 0x0008,
	RDPGFX_CMDID_CREATESURFACE 			= 0x0009,
	RDPGFX_CMDID_DELETESURFACE 			= 0x000a,
	RDPGFX_CMDID_STARTFRAME 			= 0x000b,
	RDPGFX_CMDID_ENDFRAME 				= 0x000c,
	RDPGFX_CMDID_FRAMEACKNOWLEDGE 		= 0x000d,
	RDPGFX_CMDID_RESETGRAPHICS 			= 0x000e,
	RDPGFX_CMDID_MAPSURFACETOOUTPUT 	= 0x000f,
	RDPGFX_CMDID_CACHEIMPORTOFFER 		= 0x0010,
	RDPGFX_CMDID_CACHEIMPORTREPLY 		= 0x0011,
	RDPGFX_CMDID_CAPSADVERTISE 			= 0x0012,
	RDPGFX_CMDID_CAPSCONFIRM 			= 0x0013,
	RDPGFX_CMDID_MAPSURFACETOWINDOW 	= 0x0015,
	RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE 	= 0x0016,
	RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT = 0x0017,
	RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW = 0x0018,
};

enum {
	RDPGFX_CAPVERSION_8 = 0x00080004,
	RDPGFX_CAPVERSION_81 = 0x00080105,
	RDPGFX_CAPVERSION_10 = 0x000A0002,
	RDPGFX_CAPVERSION_101 = 0x000A0100,
	RDPGFX_CAPVERSION_102 = 0x000A0200,
	RDPGFX_CAPVERSION_103 = 0x000A0301,
	RDPGFX_CAPVERSION_104 = 0x000A0400,
	RDPGFX_CAPVERSION_105 = 0x000A0502,
	RDPGFX_CAPVERSION_106_ERROR = 0x000A0600,
	RDPGFX_CAPVERSION_106 = 0x000A0601,
	RDPGFX_CAPVERSION_107 = 0x000A0701
};

enum {
	RDPGFX_CODECID_UNCOMPRESSED = 0x0000,
	RDPGFX_CODECID_CAVIDEO = 0x0003,
	RDPGFX_CODECID_CLEARCODEC = 0x0008,
	RDPGFX_CODECID_CAPROGRESSIVE = 0x0009,
	RDPGFX_CODECID_PLANAR = 0x000A,
	RDPGFX_CODECID_AVC420 = 0x000B,
	RDPGFX_CODECID_ALPHA = 0x000C,
	RDPGFX_CODECID_AVC444 = 0x000E,
	RDPGFX_CODECID_AVC444V2 = 0x000F
};

enum {
	PLANAR_HEADER_CLL = 0x07,
	PLANAR_HEADER_CS = 0x08,
	PLANAR_HEADER_RLE = 0x10,
	PLANAR_HEADER_NA = 0x20
};

enum {
	CLEARCODEC_FLAG_GLYPH_INDEX = 0x01,
	CLEARCODEC_FLAG_GLYPH_HIT = 0x02,
	CLEARCODEC_FLAG_CACHE_RESET = 0x04

};

enum {
	RFX_PROGRESSIVE_SYNC = 0xCCC0,
	RFX_PROGRESSIVE_FRAME_BEGIN = 0xCCC1,
	RFX_PROGRESSIVE_FRAME_END = 0xCCC2,
	RFX_PROGRESSIVE_CONTEXT = 0xCCC3,
	RFX_PROGRESSIVE_REGION = 0xCCC4,
	RFX_PROGRESSIVE_TILE_SIMPLE = 0xCCC5,
	RFX_PROGRESSIVE_TILE_FIRST = 0xCCC6,
	RFX_PROGRESSIVE_TILE_UPGRADE = 0xCCC7
};

static const value_string rdp_egfx_cmd_vals[] = {
	{ RDPGFX_CMDID_WIRETOSURFACE_1, "Wire to surface 1" },
	{ RDPGFX_CMDID_WIRETOSURFACE_2, "Wire to surface 2" },
	{ RDPGFX_CMDID_DELETEENCODINGCONTEXT, "delete encoding context" },
	{ RDPGFX_CMDID_SOLIDFILL, "Solid fill" },
	{ RDPGFX_CMDID_SURFACETOSURFACE, "Surface to surface" },
	{ RDPGFX_CMDID_SURFACETOCACHE, "Surface to cache" },
	{ RDPGFX_CMDID_CACHETOSURFACE, "Cache to surface" },
	{ RDPGFX_CMDID_EVICTCACHEENTRY, "Evict cache entry" },
	{ RDPGFX_CMDID_CREATESURFACE, "Create surface" },
	{ RDPGFX_CMDID_DELETESURFACE, "Delete surface" },
	{ RDPGFX_CMDID_STARTFRAME, "Start frame" },
	{ RDPGFX_CMDID_ENDFRAME, "End frame" },
	{ RDPGFX_CMDID_FRAMEACKNOWLEDGE, "Frame acknowledge" },
	{ RDPGFX_CMDID_RESETGRAPHICS, "Reset graphics" },
	{ RDPGFX_CMDID_MAPSURFACETOOUTPUT, "Map Surface to output" },
	{ RDPGFX_CMDID_CACHEIMPORTOFFER, "Cache import offer" },
	{ RDPGFX_CMDID_CACHEIMPORTREPLY, "Cache import reply" },
	{ RDPGFX_CMDID_CAPSADVERTISE, "Caps advertise" },
	{ RDPGFX_CMDID_CAPSCONFIRM, "Caps confirm" },
	{ RDPGFX_CMDID_MAPSURFACETOWINDOW, "Map surface to window" },
	{ RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE, "Qoe frame acknowledge" },
	{ RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT, "Map surface to scaled output" },
	{ RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW, "Map surface to scaled window" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_caps_version_vals[] = {
	{ RDPGFX_CAPVERSION_8, "8.0" },
	{ RDPGFX_CAPVERSION_81, "8.1" } ,
	{ RDPGFX_CAPVERSION_10, "10.0" } ,
	{ RDPGFX_CAPVERSION_101, "10.1" },
	{ RDPGFX_CAPVERSION_102, "10.2" },
	{ RDPGFX_CAPVERSION_103, "10.3" },
	{ RDPGFX_CAPVERSION_104, "10.4" },
	{ RDPGFX_CAPVERSION_105, "10.5" },
	{ RDPGFX_CAPVERSION_106_ERROR, "10.6 bogus" },
	{ RDPGFX_CAPVERSION_106, "10.6" },
	{ RDPGFX_CAPVERSION_107, "10.7" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_monitor_flags_vals[] = {
	{ 0x00000000, "is secondary" },
	{ 0x00000001, "is primary" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_codec_vals[] = {
	{ RDPGFX_CODECID_UNCOMPRESSED, "Uncompressed" },
	{ RDPGFX_CODECID_CAVIDEO, "RemoteFX" },
	{ RDPGFX_CODECID_CLEARCODEC, "Clear" },
	{ RDPGFX_CODECID_CAPROGRESSIVE, "Progressive" },
	{ RDPGFX_CODECID_PLANAR, "Planar" },
	{ RDPGFX_CODECID_AVC420, "AVC420" },
	{ RDPGFX_CODECID_ALPHA, "Alpha" },
	{ RDPGFX_CODECID_AVC444, "AVC444" },
	{ RDPGFX_CODECID_AVC444V2, "AVC444V2" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_progressive_block_types_vals[] = {
	{ RFX_PROGRESSIVE_SYNC, "WBT_SYNC" },
	{ RFX_PROGRESSIVE_FRAME_BEGIN, "WBT_FRAME_BEGIN" },
	{ RFX_PROGRESSIVE_FRAME_END, "WBT_FRAME_END" },
	{ RFX_PROGRESSIVE_CONTEXT, "WBT_CONTEXT" },
	{ RFX_PROGRESSIVE_REGION, "WBT_REGION" },
	{ RFX_PROGRESSIVE_TILE_SIMPLE, "WBT_TILE_SIMPLE" },
	{ RFX_PROGRESSIVE_TILE_FIRST, "WBT_TILE_PROGRESSIVE_FIRST" },
	{ RFX_PROGRESSIVE_TILE_UPGRADE, "WBT_TILE_PROGRESSIVE_UPGRADE" },
	{ 0x0, NULL },
};

typedef struct {
	zgfx_context_t *zgfx;
	wmem_map_t *frames;
} egfx_conv_info_t;

enum {
	EGFX_PDU_KEY = 1
};

typedef struct {
	wmem_tree_t* pdus;
} egfx_pdu_info_t;

typedef struct {
	int startNum;
	int endNum;
	int ackNum;
} egfx_frame_t;

static const char *
find_egfx_version(uint32_t v) {
	const value_string *vs = rdp_egfx_caps_version_vals;
	for ( ; vs->strptr; vs++)
		if (vs->value == v)
			return vs->strptr;

	return "<unknown>";
}

static egfx_conv_info_t *
egfx_get_conversation_data(packet_info *pinfo)
{
	conversation_t  *conversation, *conversation_tcp;
	egfx_conv_info_t *info;

	conversation = find_or_create_conversation(pinfo);

	info = (egfx_conv_info_t *)conversation_get_proto_data(conversation, proto_rdp_egfx);
	if (!info) {
		conversation_tcp = rdp_find_tcp_conversation_from_udp(conversation);
		if (conversation_tcp)
			info = (egfx_conv_info_t *)conversation_get_proto_data(conversation_tcp, proto_rdp_egfx);
	}

	if (info == NULL) {
		info = wmem_new0(wmem_file_scope(), egfx_conv_info_t);
		info->zgfx = zgfx_context_new(wmem_file_scope());
		info->frames = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation, proto_rdp_egfx, info);
	}

	return info;
}


static int
dissect_rdp_egfx_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, egfx_conv_info_t *conv, void *data _U_)
{
	proto_item *item;
	proto_item *pi;
	proto_tree *tree;
	proto_tree *subtree;
	int offset = 0;
	uint32_t cmdId = 0;
	uint32_t pduLength;
	uint32_t i;

	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EGFX");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_captured_length_remaining(tvb, offset) > 8) {
		pduLength = tvb_get_uint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);

		item = proto_tree_add_item(parent_tree, proto_rdp_egfx, tvb, offset, pduLength, ENC_NA);
		tree = proto_item_add_subtree(item, ett_rdp_egfx);

		proto_tree_add_item_ret_uint(tree, hf_egfx_cmdId, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cmdId);
		offset += 2;

		proto_tree_add_item(tree, hf_egfx_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tree, hf_egfx_pduLength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		if (pduLength < 8) {
			expert_add_info_format(pinfo, item, &ei_egfx_pdulen_invalid, "pduLength is %u, not < 8", pduLength);
			return offset;
		}

		int nextOffset = offset + (pduLength - 8);
		switch (cmdId) {
		case RDPGFX_CMDID_CAPSADVERTISE: {
			uint16_t capsSetCount = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Caps advertise");
			proto_tree_add_item(tree, hf_egfx_caps_capsSetCount, tvb, offset, 2, ENC_LITTLE_ENDIAN);

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_caps, NULL, "Caps");
			offset += 2;

			for (i = 0; i < capsSetCount; i++) {
				uint32_t version = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
				uint32_t capsDataLength = tvb_get_uint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);
				proto_tree* vtree = proto_tree_add_subtree(subtree, tvb, offset, 8 + capsDataLength, ett_egfx_cap_version, NULL, find_egfx_version(version));

				proto_tree_add_item(vtree, hf_egfx_cap_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(vtree, hf_egfx_cap_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				offset += capsDataLength;
			}
			break;
		}

		case RDPGFX_CMDID_CAPSCONFIRM: {
			uint32_t capsDataLength;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Caps confirm");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_capsconfirm, NULL, "Caps confirm");
			proto_tree_add_item(subtree, hf_egfx_cap_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_cap_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &capsDataLength);
			break;
		}

		case RDPGFX_CMDID_RESETGRAPHICS: {
			uint32_t nmonitor;
			proto_tree *monitors_tree;
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Reset graphics");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_reset, NULL, "Reset graphics");
			proto_tree_add_item(subtree, hf_egfx_reset_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_reset_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_reset_monitorCount, tvb, offset, 4, ENC_LITTLE_ENDIAN, &nmonitor);
			offset += 4;

			monitors_tree = proto_tree_add_subtree(subtree, tvb, offset, nmonitor * 20, ett_egfx_monitors, NULL, "Monitors");
			for (i = 0; i < nmonitor; i++) {
				proto_item *monitor_tree;
				uint32_t left, top, right, bottom;
				left = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
				top = tvb_get_uint32(tvb, offset+4, ENC_LITTLE_ENDIAN);
				right = tvb_get_uint32(tvb, offset+8, ENC_LITTLE_ENDIAN);
				bottom = tvb_get_uint32(tvb, offset+12, ENC_LITTLE_ENDIAN);

				monitor_tree = proto_tree_add_subtree_format(monitors_tree, tvb, offset, 20, ett_egfx_monitordef, NULL,
						"(%d,%d) - (%d,%d)", left, top, right, bottom);

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefLeft, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefTop, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefRight, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefBottom, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefFlags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
			}
			break;
		}

		case RDPGFX_CMDID_STARTFRAME: {
			uint32_t frameId;
			egfx_frame_t *frame;
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Start frame");
			proto_tree_add_item(tree, hf_egfx_start_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			// TODO: dissect timestamp
			offset += 4;

			proto_tree_add_item_ret_uint(tree, hf_egfx_start_frameid, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);
			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = pinfo->num;
				frame->endNum = -1;
				frame->ackNum = -1;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			if (PINFO_FD_VISITED(pinfo) && frame->ackNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_start_acked_in, tvb, 0, 0, frame->ackNum);
				proto_item_set_generated(pi);
			}
			break;
		}

		case RDPGFX_CMDID_ENDFRAME: {
			uint32_t frameId;
			egfx_frame_t *frame;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "End frame");
			proto_tree_add_item_ret_uint(tree, hf_egfx_end_frameid, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);

			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = -1;
				frame->ackNum = -1;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			frame->endNum = pinfo->num;

			if (PINFO_FD_VISITED(pinfo) && frame->ackNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_end_acked_in, tvb, 0, 0, frame->ackNum);
				proto_item_set_generated(pi);
			}

			break;
		}

		case RDPGFX_CMDID_FRAMEACKNOWLEDGE: {
			uint32_t frameId;
			egfx_frame_t *frame;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Frame acknowledge");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_ack, NULL, "Frame acknowledge");
			proto_tree_add_item(subtree, hf_egfx_ack_queue_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_ack_frame_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ack_total_decoded, tvb, offset, 4, ENC_LITTLE_ENDIAN);

			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = -1;
				frame->endNum = -1;
				frame->ackNum = frameId;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			frame->ackNum = pinfo->num;

			if (PINFO_FD_VISITED(pinfo) && frame->startNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ack_frame_start, tvb, 0, 0, frame->startNum);
				proto_item_set_generated(pi);
			}

			if (PINFO_FD_VISITED(pinfo) && frame->endNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ack_frame_end, tvb, 0, 0, frame->endNum);
				proto_item_set_generated(pi);
			}
			break;
		}

		case RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE: {
			uint32_t frameId;
			egfx_frame_t *frame;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Frame acknowledge QoE");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_ackqoe, NULL, "Frame acknowledge QoE");
			proto_tree_add_item_ret_uint(subtree, hf_egfx_ackqoe_frame_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timediffse, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timediffedr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = -1;
				frame->endNum = -1;
				frame->ackNum = frameId;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			frame->ackNum = pinfo->num;

			if (PINFO_FD_VISITED(pinfo) && frame->startNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ackqoe_frame_start, tvb, 0, 0, frame->startNum);
				proto_item_set_generated(pi);
			}

			if (PINFO_FD_VISITED(pinfo) && frame->endNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ackqoe_frame_end, tvb, 0, 0, frame->endNum);
				proto_item_set_generated(pi);
			}

			break;
		}

		case RDPGFX_CMDID_CREATESURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Create Surface");
			break;

		case RDPGFX_CMDID_MAPSURFACETOOUTPUT:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Output");
			break;

		case RDPGFX_CMDID_WIRETOSURFACE_1: {
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Wire To Surface 1");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_w2s1, NULL, "Wire To Surface 1");
			proto_tree_add_item(subtree, hf_egfx_w2s1_surface_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			uint16_t codecid = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_egfx_w2s1_codec_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_w2s1_pixel_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			proto_item *dest_rect_tree;
			dest_rect_tree = proto_tree_add_subtree(subtree, tvb, offset, 8, ett_egfx_w2s1_rect, NULL, "Target rect");

			proto_tree_add_item(dest_rect_tree, hf_egfx_w2s1_dest_rectLeft, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(dest_rect_tree, hf_egfx_w2s1_dest_rectTop, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(dest_rect_tree, hf_egfx_w2s1_dest_rectRight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(dest_rect_tree, hf_egfx_w2s1_dest_rectBottom, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			uint32_t data_size = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_egfx_w2s1_bitmap_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree *bitmap_tree;
			bitmap_tree = proto_tree_add_subtree(subtree, tvb, offset, pduLength-25, ett_egfx_w2s1_bitmap, NULL, "Bitmap data");

			switch (codecid) {
				case RDPGFX_CODECID_PLANAR: {
					// uint8_t header = tvb_get_uint8(tvb, offset);
					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_planar_header_cll, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_planar_header_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_planar_header_rle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_planar_header_na, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset++;
					break;
				}
				case RDPGFX_CODECID_CLEARCODEC: {
					uint8_t flags = tvb_get_uint8(tvb, offset);
					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_clear_flag_glyph_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_clear_flag_glyph_hit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_clear_flag_cache_reset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset++;

					proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_clear_seq_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset++;

					if (flags & CLEARCODEC_FLAG_GLYPH_INDEX)
					{
						proto_tree_add_item(bitmap_tree, hf_egfx_w2s1_bitmap_data_clear_glyph_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						offset += 2;
					}
					else if (!(flags & CLEARCODEC_FLAG_GLYPH_HIT))
					{
						proto_tree *composite_payload_tree;
						composite_payload_tree = proto_tree_add_subtree(bitmap_tree, tvb, offset, data_size - 2, ett_egfx_w2s1_composite_payload, NULL, "Composite payload");
						offset += data_size - 2;
					}
					break;
				}
			}

			break;
		}

		case RDPGFX_CMDID_WIRETOSURFACE_2: {
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Wire To Surface 2");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_w2s2, NULL, "Wire To Surface 2");
			proto_tree_add_item(subtree, hf_egfx_w2s2_surface_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			uint16_t codecid = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_egfx_w2s2_codec_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_w2s2_codec_context_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_w2s2_pixel_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			uint32_t bitmap_size = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_egfx_w2s2_bitmap_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree *bitmap_tree;
			bitmap_tree = proto_tree_add_subtree(subtree, tvb, offset, pduLength-21, ett_egfx_w2s2_bitmap, NULL, "Bitmap data");

			int block_count = 0;
			switch (codecid) {
				case RDPGFX_CODECID_CAPROGRESSIVE: {
					while(bitmap_size) {
						proto_tree *block_tree = proto_tree_add_subtree(bitmap_tree, tvb, offset, 6, ett_egfx_w2s2_block, NULL, NULL);

						uint16_t block_type = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_block_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);

						uint32_t block_size = tvb_get_uint32(tvb, offset + 2, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_block_len, tvb, offset + 2, 4, ENC_LITTLE_ENDIAN);

						switch (block_type) {
							case RFX_PROGRESSIVE_SYNC:
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_sync_magic, tvb, offset + 6, 4, ENC_LITTLE_ENDIAN);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_sync_version, tvb, offset + 10, 2, ENC_LITTLE_ENDIAN);
								break;
							case RFX_PROGRESSIVE_FRAME_BEGIN:
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_frame_index, tvb, offset + 6, 4, ENC_LITTLE_ENDIAN);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_frame_reg_count, tvb, offset + 10, 2, ENC_LITTLE_ENDIAN);
								// TODO regions array
								break;
							case RFX_PROGRESSIVE_FRAME_END:
								// Nothing to do!
								break;
							case RFX_PROGRESSIVE_CONTEXT:
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_ctx_context_id, tvb, offset + 6, 1, ENC_LITTLE_ENDIAN);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_ctx_tile_size, tvb, offset + 7, 2, ENC_LITTLE_ENDIAN);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_ctx_flags, tvb, offset + 9, 1, ENC_LITTLE_ENDIAN);
								break;
							case RFX_PROGRESSIVE_REGION: {
								uint32_t __offset = offset + 6;
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_region_tile_size, tvb, __offset, 1, ENC_LITTLE_ENDIAN);
								__offset++;

								uint16_t rects_count = tvb_get_uint16(tvb, __offset, ENC_LITTLE_ENDIAN);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_region_num_rects, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
								__offset += 2;
								uint8_t quant_count = tvb_get_uint8(tvb, __offset);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_region_num_quant, tvb, __offset, 1, ENC_LITTLE_ENDIAN);
								__offset++;
								uint8_t prog_quant_count = tvb_get_uint8(tvb, __offset);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_region_num_prog_quant, tvb, __offset, 1, ENC_LITTLE_ENDIAN);
								__offset++;
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_region_flags, tvb, __offset, 1, ENC_LITTLE_ENDIAN);
								__offset++;
								uint16_t tiles_count = tvb_get_uint16(tvb, __offset, ENC_LITTLE_ENDIAN);
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_region_num_tiles, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
								__offset += 2;
								proto_tree_add_item(block_tree, hf_egfx_w2s2_progressive_region_tiles_data_size, tvb, __offset, 4, ENC_LITTLE_ENDIAN);
								__offset += 4;
								
								while(rects_count--) {
									proto_tree *rects_tree = proto_tree_add_subtree(block_tree, tvb, __offset, 8, ett_egfx_w2s2_region_rects, NULL, "Rect");
									proto_tree_add_item(rects_tree, hf_egfx_w2s2_progressive_region_rect_x, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
									__offset += 2;
									proto_tree_add_item(rects_tree, hf_egfx_w2s2_progressive_region_rect_y, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
									__offset += 2;
									proto_tree_add_item(rects_tree, hf_egfx_w2s2_progressive_region_rect_width, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
									__offset += 2;
									proto_tree_add_item(rects_tree, hf_egfx_w2s2_progressive_region_rect_height, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
									__offset += 2;
								}

								while(quant_count--) {
									/*proto_tree *quant_tree =*/ proto_tree_add_subtree(block_tree, tvb, __offset, 5, ett_egfx_w2s2_region_rects, NULL, "Quant");
									__offset += 5;
									// proto_tree_add_item(quant_tree, hf_egfx_w2s2_progressive_region_rect_x, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
									// __offset += 2;
								}

								while(prog_quant_count--) {
									/*proto_tree *prog_quant_tree =*/ proto_tree_add_subtree(block_tree, tvb, __offset, 16, ett_egfx_w2s2_region_rects, NULL, "Quant (progressive)");
									__offset += 16;
									// proto_tree_add_item(prog_quant_tree, hf_egfx_w2s2_progressive_region_rect_x, tvb, __offset, 2, ENC_LITTLE_ENDIAN);
									// __offset += 2;
								}

								while(tiles_count--) {
									uint32_t tile_offset = __offset;
									proto_tree *tiles_tree = proto_tree_add_subtree(block_tree, tvb, tile_offset, 0, ett_egfx_w2s2_region_tiles, NULL, NULL);
						
									uint16_t block_type = tvb_get_uint16(tvb, tile_offset, ENC_LITTLE_ENDIAN);
									proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_type, tvb, tile_offset, 2, ENC_LITTLE_ENDIAN);
									tile_offset += 2;

									uint32_t block_size = tvb_get_uint32(tvb, tile_offset, ENC_LITTLE_ENDIAN);
									proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 4, ENC_LITTLE_ENDIAN);
									tile_offset += 4;

									switch (block_type) {
										case RFX_PROGRESSIVE_TILE_FIRST:
										case RFX_PROGRESSIVE_TILE_SIMPLE: {
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset++;
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset++;
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset++;
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset += 2;
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset += 2;

											if (block_type != RFX_PROGRESSIVE_TILE_UPGRADE)
											{
												// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
												tile_offset++;
											}

											if (block_type == RFX_PROGRESSIVE_TILE_FIRST || block_type == RFX_PROGRESSIVE_TILE_UPGRADE)
											{
												// Progressive Quality
												// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
												tile_offset++;
											}

											uint16_t yLen = tvb_get_uint16(tvb, tile_offset, ENC_LITTLE_ENDIAN);
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset += 2;
											uint16_t cbLen = tvb_get_uint16(tvb, tile_offset, ENC_LITTLE_ENDIAN);
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset += 2;
											uint16_t crLen = tvb_get_uint16(tvb, tile_offset, ENC_LITTLE_ENDIAN);
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset += 2;
											uint16_t tilelen = tvb_get_uint16(tvb, tile_offset, ENC_LITTLE_ENDIAN);
											// proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_block_len, tvb, tile_offset, 1, ENC_LITTLE_ENDIAN);
											tile_offset += 2;

											proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_region_tile_ydata, tvb, tile_offset, yLen, ENC_LITTLE_ENDIAN);
											tile_offset += yLen;
											proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_region_tile_cbdata, tvb, tile_offset, cbLen, ENC_LITTLE_ENDIAN);
											tile_offset += cbLen;
											proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_region_tile_crdata, tvb, tile_offset, crLen, ENC_LITTLE_ENDIAN);
											tile_offset += crLen;
											if (tilelen)
											{
												proto_tree_add_item(tiles_tree, hf_egfx_w2s2_progressive_region_tile_data, tvb, tile_offset, tilelen, ENC_LITTLE_ENDIAN);
												tile_offset += tilelen;
											}
											break;
										}
										case RFX_PROGRESSIVE_TILE_UPGRADE:
										default:
											break;
									}		

									proto_item_set_len(tiles_tree, block_size);
									proto_item_set_text(tiles_tree, "Tile (0x%0.4X)", block_type);
									__offset += block_size;
								}

								break;
							}
						}

						proto_item_set_len(block_tree, block_size);
						proto_item_set_text(block_tree, "Block %d (0x%0.4X)", ++block_count, block_type);
						offset += block_size;
						bitmap_size -= block_size;
					}
					break;
				}
			}

			break;
		}

		case RDPGFX_CMDID_DELETEENCODINGCONTEXT:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Delete Encoding Context");
			break;

		case RDPGFX_CMDID_SOLIDFILL:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Solid Fill");
			break;

		case RDPGFX_CMDID_SURFACETOSURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Surface To Surface");
			break;

		case RDPGFX_CMDID_SURFACETOCACHE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Surface To Cache");
			break;

		case RDPGFX_CMDID_CACHETOSURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Cache To Surface");
			break;

		case RDPGFX_CMDID_EVICTCACHEENTRY:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Evict Cache Entry");
			break;

		case RDPGFX_CMDID_DELETESURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Delete Surface");
			break;

		case RDPGFX_CMDID_CACHEIMPORTOFFER:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Cache Import Offer");
			break;

		case RDPGFX_CMDID_CACHEIMPORTREPLY:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Cache Import Reply");
			break;

		case RDPGFX_CMDID_MAPSURFACETOWINDOW:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Window");
			break;

		case RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Scaled Output");
			break;

		case RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Scaled Window");
			break;

		default:
			break;
		}

		offset = nextOffset;
	}
	return offset;
}

static int
dissect_rdp_egfx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	tvbuff_t *work_tvb = tvb;
	egfx_conv_info_t *infos = egfx_get_conversation_data(pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EGFX");
	col_clear(pinfo->cinfo, COL_INFO);

	parent_tree = proto_tree_get_root(parent_tree);

	if (!rdp_isServerAddressTarget(pinfo)) {
		uint32_t hash = crc32_ccitt_tvb(tvb, tvb_captured_length_remaining(tvb, 0));
		egfx_pdu_info_t *pdu_infos = p_get_proto_data(wmem_file_scope(), pinfo, proto_rdp_egfx, EGFX_PDU_KEY);
		if (!pdu_infos) {
			pdu_infos = wmem_alloc(wmem_file_scope(), sizeof(*pdu_infos));
			pdu_infos->pdus = wmem_tree_new(wmem_file_scope());
			p_set_proto_data(wmem_file_scope(), pinfo, proto_rdp_egfx, EGFX_PDU_KEY, pdu_infos);
		}

		if (!PINFO_FD_VISITED(pinfo)) {
			work_tvb = rdp8_decompress(infos->zgfx, wmem_file_scope(), tvb, 0);
			if (work_tvb) {
				//printf("%d: zgfx sz=%d\n", pinfo->num, tvb_captured_length(work_tvb));
				wmem_tree_insert32(pdu_infos->pdus, hash, work_tvb);
			}
		} else {
			pdu_infos = p_get_proto_data(wmem_file_scope(), pinfo, proto_rdp_egfx, EGFX_PDU_KEY);
			work_tvb = wmem_tree_lookup32(pdu_infos->pdus, hash);
		}

		if (work_tvb)
			add_new_data_source(pinfo, work_tvb, "Uncompressed GFX");
	}

	if (work_tvb)
		dissect_rdp_egfx_payload(work_tvb, pinfo, parent_tree, infos, data);
	else {
		if (parent_tree)
			expert_add_info_format(pinfo, parent_tree->last_child, &ei_egfx_invalid_compression, "invalid compression");
	}

	return tvb_reported_length(tvb);
}


void proto_register_rdp_egfx(void) {
	static hf_register_info hf[] = {
		{ &hf_egfx_cmdId,
		  { "CmdId", "rdp_egfx.cmdid",
		    FT_UINT16, BASE_HEX, VALS(rdp_egfx_cmd_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_flags,
		  { "flags", "rdp_egfx.flags",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_pduLength,
		  { "pduLength", "rdp_egfx.pdulength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_caps_capsSetCount,
		  { "capsSetCount", "rdp_egfx.caps.setcount",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_version,
		  { "Version", "rdp_egfx.cap.version",
			FT_UINT32, BASE_HEX, VALS(rdp_egfx_caps_version_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_length,
		  { "capsDataLength", "rdp_egfx.cap.length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_queue_depth,
		  { "queueDepth", "rdp_egfx.ack.queuedepth",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_frame_id,
		  { "frameId", "rdp_egfx.ack.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_total_decoded,
		  { "Total frames decoded", "rdp_egfx.ack.totalframesdecoded",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_frame_start,
		  { "Frame starts in", "rdp_egfx.ack.framestart",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_frame_end,
		  { "Frame ends in", "rdp_egfx.ack.frameend",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_frame_id,
		  { "frameId", "rdp_egfx.ackqoe.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_timestamp,
		  { "Timestamp", "rdp_egfx.ackqoe.timestamp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_timediffse,
		  { "TimeDiffSE", "rdp_egfx.ackqoe.timediffse",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_timediffedr,
		  { "TimeDiffEDR", "rdp_egfx.ackqoe.timediffedr",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_frame_start,
		  { "Frame starts in", "rdp_egfx.ackqoe.framestart",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_frame_end,
		  { "Frame ends in", "rdp_egfx.ackqoe.frameend",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_width,
		  { "Width", "rdp_egfx.reset.width",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_height,
		  { "Height", "rdp_egfx.reset.height",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorCount,
		  { "Monitor count", "rdp_egfx.reset.monitorcount",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefLeft,
		  { "Left", "rdp_egfx.monitor.left",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefTop,
		  { "Top", "rdp_egfx.monitor.top",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefRight,
		  { "Right", "rdp_egfx.monitor.right",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefBottom,
		  { "Bottom", "rdp_egfx.monitor.bottom",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefFlags,
		  { "Flags", "rdp_egfx.monitor.flags",
			FT_UINT32, BASE_HEX, VALS(rdp_egfx_monitor_flags_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_start_timestamp,
		  { "Timestamp", "rdp_egfx.startframe.timestamp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_start_frameid,
		  { "Frame id", "rdp_egfx.startframe.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_start_acked_in,
		  { "Frame acked in", "rdp_egfx.startframe.ackedin",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			NULL, HFILL }
		},

		{ &hf_egfx_end_frameid,
		  { "Frame id", "rdp_egfx.endframe.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_end_acked_in,
		  { "Frame acked in", "rdp_egfx.endframe.ackedin",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_surface_id,
		  { "Surface ID", "rdp_egfx.w2s1.surfaceid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_codec_id,
		  { "Codec ID", "rdp_egfx.w2s1.codecid",
		    FT_UINT16, BASE_HEX, VALS(rdp_egfx_codec_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_pixel_format,
		  { "Pixel format", "rdp_egfx.w2s1.pixelfmt",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_dest_rectLeft,
		  { "Left", "rdp_egfx.w2s1.targetrect.left",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_dest_rectTop,
		  { "Top", "rdp_egfx.w2s1.targetrect.top",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_dest_rectRight,
		  { "Right", "rdp_egfx.w2s1.targetrect.right",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_dest_rectBottom,
		  { "Bottom", "rdp_egfx.w2s1.targetrect.bottom",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_size,
		  { "Bitmap data size", "rdp_egfx.w2s1.bitmapsize",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_planar_header_cll,
		  { "CLL", "rdp_egfx.w2s1.bitmap.planar.header.cll",
			FT_UINT8, BASE_HEX, NULL, PLANAR_HEADER_CLL,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_planar_header_cs,
		  { "CS", "rdp_egfx.w2s1.bitmap.planar.header.cs",
			FT_UINT8, BASE_HEX, NULL, PLANAR_HEADER_CS,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_planar_header_rle,
		  { "RLE", "rdp_egfx.w2s1.bitmap.planar.header.rle",
			FT_UINT8, BASE_HEX, NULL, PLANAR_HEADER_RLE,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_planar_header_na,
		  { "NA", "rdp_egfx.w2s1.bitmap.planar.header.na",
			FT_UINT8, BASE_HEX, NULL, PLANAR_HEADER_NA,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_clear_flag_glyph_index,
		  { "Glyph index", "rdp_egfx.w2s1.bitmap.clearcodec.flag.glyph.index",
		    FT_UINT8, BASE_HEX, NULL, CLEARCODEC_FLAG_GLYPH_INDEX,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_clear_flag_glyph_hit,
		  { "Glyph hit", "rdp_egfx.w2s1.bitmap.clearcodec.flag.glyph.hit",
		    FT_UINT8, BASE_HEX, NULL, CLEARCODEC_FLAG_GLYPH_HIT,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_clear_flag_cache_reset,
		  { "Cache reset", "rdp_egfx.w2s1.bitmap.clearcodec.flag.cachereset",
		    FT_UINT8, BASE_HEX, NULL, CLEARCODEC_FLAG_CACHE_RESET,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_clear_seq_num,
		  { "Seq num", "rdp_egfx.w2s1.bitmap.clearcodec.seq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s1_bitmap_data_clear_glyph_index,
		  { "Glyph index", "rdp_egfx.w2s1.bitmap.clearcodec.glyph.index",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_surface_id,
		  { "Surface ID", "rdp_egfx.w2s2.surfaceid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_codec_id,
		  { "Codec ID", "rdp_egfx.w2s2.codecid",
		    FT_UINT16, BASE_HEX, VALS(rdp_egfx_codec_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_codec_context_id,
		  { "Codec context ID", "rdp_egfx.w2s2.codeccontextid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_pixel_format,
		  { "Pixel format", "rdp_egfx.w2s2.pixelfmt",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_bitmap_data_size,
		  { "Bitmap data size", "rdp_egfx.w2s2.bitmapsize",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_block_type,
		  { "Block type", "rdp_egfx.w2s2.progressive.block.type",
		    FT_UINT16, BASE_HEX, VALS(rdp_egfx_progressive_block_types_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_block_len,
		  { "Block length", "rdp_egfx.w2s2.progressive.block.length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_sync_magic,
		  { "Magic", "rdp_egfx.w2s2.progressive.sync.magic",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_sync_version,
		  { "Version", "rdp_egfx.w2s2.progressive.sync.version",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_frame_index,
		  { "Index", "rdp_egfx.w2s2.progressive.frame.index",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_frame_reg_count,
		  { "Reg count", "rdp_egfx.w2s2.progressive.frame.regcount",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_ctx_context_id,
		  { "CtxID", "rdp_egfx.w2s2.progressive.context.id",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_ctx_tile_size,
		  { "Tile size", "rdp_egfx.w2s2.progressive.context.tilesize",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_ctx_flags,
		  { "Flags", "rdp_egfx.w2s2.progressive.context.flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_tile_size,
		  { "Tile size", "rdp_egfx.w2s2.progressive.region.tilesize",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_num_rects,
		  { "Rects count", "rdp_egfx.w2s2.progressive.region.numrects",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_num_quant,
		  { "Quant count", "rdp_egfx.w2s2.progressive.region.numquant",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_num_prog_quant,
		  { "Quant-prog count", "rdp_egfx.w2s2.progressive.region.numprogquant",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_flags,
		  { "Flags", "rdp_egfx.w2s2.progressive.region.flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_num_tiles,
		  { "Tiles count", "rdp_egfx.w2s2.progressive.region.numtiles",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_tiles_data_size,
		  { "Data size", "rdp_egfx.w2s2.progressive.region.datasize",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_rect_x,
		  { "X", "rdp_egfx.w2s2.progressive.region.rect.x",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_rect_y,
		  { "Y", "rdp_egfx.w2s2.progressive.region.rect.y",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_rect_width,
		  { "Width", "rdp_egfx.w2s2.progressive.region.rect.width",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_rect_height,
		  { "Height", "rdp_egfx.w2s2.progressive.region.rect.height",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_tile_ydata,
		  { "Y Data", "rdp_egfx.w2s2.progressive.region.tile.ydata",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_tile_cbdata,
		  { "CB Data", "rdp_egfx.w2s2.progressive.region.tile.cbdata",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_tile_crdata,
		  { "CR Data", "rdp_egfx.w2s2.progressive.region.tile.crdata",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_w2s2_progressive_region_tile_data,
		  { "Data", "rdp_egfx.w2s2.progressive.region.tile.data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_rdp_egfx,
		&ett_egfx_caps,
		&ett_egfx_cap,
		&ett_egfx_cap_version,
		&ett_egfx_ack,
		&ett_egfx_ackqoe,
		&ett_egfx_reset,
		&ett_egfx_capsconfirm,
		&ett_egfx_monitors,
		&ett_egfx_monitordef,
		&ett_egfx_w2s1,
		&ett_egfx_w2s1_rect,
		&ett_egfx_w2s1_bitmap,
		&ett_egfx_w2s2,
		&ett_egfx_w2s2_bitmap,
		&ett_egfx_w2s2_block,
		&ett_egfx_w2s2_region_rects,
		&ett_egfx_w2s2_region_quants,
		&ett_egfx_w2s2_region_prog_quants,
		&ett_egfx_w2s2_region_tiles,
	};

	static ei_register_info ei[] = {
		{ &ei_egfx_pdulen_invalid, { "rdp_egfx.pdulength.invalid", PI_PROTOCOL, PI_ERROR, "Invalid length", EXPFILL }},
		{ &ei_egfx_invalid_compression, { "rdp_egfx.compression.invalid", PI_PROTOCOL, PI_ERROR, "Invalid compression", EXPFILL }},
	};
	expert_module_t* expert_egfx;


	proto_rdp_egfx = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_egfx, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_egfx = expert_register_protocol(proto_rdp_egfx);
	expert_register_field_array(expert_egfx, ei, array_length(ei));

	register_dissector("rdp_egfx", dissect_rdp_egfx, proto_rdp_egfx);
}

void proto_reg_handoff_rdp_egfx(void) {
}
