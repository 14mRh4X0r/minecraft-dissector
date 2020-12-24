#define WS_BUILD_DLL

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <ws_attributes.h>
#include <ws_symbol_export.h>
#include <ws_version.h>
#include <stdbool.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

static void minecraft_add_varint(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset);
static void minecraft_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset);
static void minecraft_add_u8(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset);
static void minecraft_add_i8(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset);
static void minecraft_add_u16(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset);
static void minecraft_add_i16(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset);
static void minecraft_add_i64(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset);


#include "generated.h"

static int proto_minecraft = -1;
static int hf_length = -1;
static int hf_data_length = -1;
static int hf_packet_id = -1;
static int hf_data = -1;

static hf_register_info hf[] = {

    { &hf_length,
        { "Length", "minecraft.length", FT_UINT32, BASE_DEC, NULL,
            0x00, "Packet Length", HFILL }},

    { &hf_data_length,
        { "Data Length", "minecraft.data_length", FT_UINT32, BASE_DEC, NULL,
            0x00, "Packet Data Length", HFILL }},

    { &hf_packet_id,
        { "Packet Id", "minecraft.packet_id", FT_UINT8, BASE_HEX, NULL,
            0x0, "Packet Id", HFILL }},

    { &hf_data,
        { "Data", "minecraft.data", FT_BYTES, BASE_NONE, NULL,
            0x0, "Packet Data", HFILL }},
};

static int ett_minecraft = -1;
static int ett_data = -1;

static gint *ett[] = {
    &ett_minecraft,
    &ett_data,
};


static bool read_varint(guint32 *result, tvbuff_t *tvb, guint *offset) {
    *result = 0;
    guint shift = 0;

    const guint length = tvb_reported_length(tvb);
    while (*offset < length && shift <= 35) {
        const guint8 b = tvb_get_guint8(tvb, *offset);
        *result |= ((b & 0x7fu) << shift);
        *offset += 1;
        shift += 7;
        if ((b & 0x80u) == 0) /* End of varint */
            return true;
    }
    return false;
}

static void minecraft_add_varint(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset) {
    const guint offset_start = *offset;
    guint32 value = 0;
    read_varint(&value, tvb, offset);
    proto_tree_add_uint(tree, hfindex, tvb, offset_start, *offset - offset_start, value);
}

static void minecraft_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset) {
    const guint offset_start = *offset;
    guint32 len = 0;
    read_varint(&len, tvb, offset);
    guchar *data = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, len, ENC_UTF_8);
    proto_tree_add_string(tree, hfindex, tvb, offset_start, *offset - offset_start + len, (gchar*) data);
    *offset += len;
}

static void minecraft_add_u8(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset) {
    const guint8 v = tvb_get_guint8(tvb, *offset);
    proto_tree_add_uint(tree, hfindex, tvb, *offset, 1, v);
    *offset += 1;
}

static void minecraft_add_i8(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset) {
    const gint8 v = tvb_get_gint8(tvb, *offset);
    proto_tree_add_int(tree, hfindex, tvb, *offset, 1, v);
    *offset += 1;
}

static void minecraft_add_u16(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset) {
    const guint16 v = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_uint(tree, hfindex, tvb, *offset, 2, v);
    *offset += 2;
}

static void minecraft_add_i16(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset) {
    const gint16 v = tvb_get_ntohis(tvb, *offset);
    proto_tree_add_int(tree, hfindex, tvb, *offset, 2, v);
    *offset += 2;
}

static void minecraft_add_i64(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset) {
    const gint64 v = tvb_get_ntohi48(tvb, *offset);
    proto_tree_add_int64(tree, hfindex, tvb, *offset, 2, v);
    *offset += 2;
}


struct minecraft_conversation_data {
    guint32 state;
    guint32 compression_threshold;
};

struct minecraft_frame_data {
    guint32 state;
    bool compressed;
};


static void dissect_minecraft_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint32 len)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Minecraft");

    conversation_t *conversation = find_or_create_conversation(pinfo);

    struct minecraft_conversation_data *conversation_data = (struct minecraft_conversation_data *)conversation_get_proto_data(conversation, proto_minecraft);
    if (conversation_data == NULL) {
        conversation_data = wmem_new0(wmem_file_scope(), struct minecraft_conversation_data);
        conversation_data->state = 0;
        conversation_data->compression_threshold = 0;
        conversation_add_proto_data(conversation, proto_minecraft, conversation_data);
    }

    struct minecraft_frame_data *frame_data = (struct minecraft_frame_data  *)p_get_proto_data(wmem_file_scope(), pinfo, proto_minecraft, 0);
    if (frame_data == NULL) {
        frame_data = wmem_new(wmem_file_scope(), struct minecraft_frame_data);
        frame_data->state = conversation_data->state;
        frame_data->compressed = conversation_data->compression_threshold != 0;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_minecraft, 0, frame_data);
    }

    if (frame_data->compressed) {
        const guint offset_start = offset;
        guint32 data_length;
        read_varint(&data_length, tvb, &offset);
        proto_tree_add_uint(tree, hf_data_length, tvb, offset_start, offset - offset_start, data_length);

        len -= (offset - offset_start);

        if (data_length != 0) {
            tvb = tvb_uncompress(tvb, offset, len);
            offset = 0;
            len = data_length;
        }
    }

    bool to_server = pinfo->destport == pinfo->match_uint;

    const guint offset_start = offset;
    guint32 packet_id;
    read_varint(&packet_id, tvb, &offset);
    const guint packet_id_len = offset - offset_start;
    proto_tree_add_uint(tree, hf_packet_id, tvb, offset_start, packet_id_len, packet_id);

    const guint data_len = len - packet_id_len;
    proto_item *data_item = proto_tree_add_item(tree, hf_data, tvb, offset, data_len, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(data_item, ett_data);

    switch (frame_data->state) {
        case 0:
            if (to_server) {
                handshaking_toServer(packet_id, tvb, pinfo, subtree, offset, data_len);

                if (packet_id == 0x00) {
                    conversation_data->state = tvb_get_guint8(tvb, offset + data_len - 1);
                }
            } else
                handshaking_toClient(packet_id, tvb, pinfo, subtree, offset, data_len);
            break;
        case 1:
            if (to_server)
                status_toServer(packet_id, tvb, pinfo, subtree, offset, data_len);
            else
                status_toClient(packet_id, tvb, pinfo, subtree, offset, data_len);
            break;
        case 2:
            if (to_server)
                login_toServer(packet_id, tvb, pinfo, subtree, offset, data_len);
            else {
                login_toClient(packet_id, tvb, pinfo, subtree, offset, data_len);

                switch (packet_id) {
                    case 0x02:
                        conversation_data->state = 3;
                        break;
                    case 0x03:
                        read_varint(&conversation_data->compression_threshold, tvb, &offset);
                        break;
                }
            }
            break;
        case 3:
            if (to_server)
                play_toServer(packet_id, tvb, pinfo, subtree, offset, data_len);
            else
                play_toClient(packet_id, tvb, pinfo, subtree, offset, data_len);
            break;
    }
}

static int dissect_minecraft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    while (offset < tvb_reported_length(tvb)) {
        guint available = tvb_reported_length_remaining(tvb, offset);
        guint32 len = 0;
        const guint offset_start = offset;
        if (read_varint(&len, tvb, &offset) == false) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return (int) (offset + available);
        }

        if (len > available) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = len - available;
            return (int) (offset + available);
        }

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Minecraft");

        proto_item *item = proto_tree_add_item(tree, proto_minecraft, tvb, offset, len, ENC_NA);

        proto_tree *subtree = proto_item_add_subtree(item, ett_minecraft);

        proto_tree_add_uint(subtree, hf_length, tvb, offset_start, offset - offset_start, len);

        dissect_minecraft_packet(tvb, pinfo, subtree, offset, len);

        offset += len;
    }

    return tvb_captured_length(tvb);
}

static void proto_register_minecraft(void)
{
    proto_minecraft = proto_register_protocol("Minecraft Protocol", "Minecraft", "minecraft");

    proto_register_field_array(proto_minecraft, hf, array_length(hf));
    proto_register_field_array(proto_minecraft, hf_generated, array_length(hf_generated));
    proto_register_subtree_array(ett, array_length(ett));
}

static void proto_reg_handoff_minecraft(void)
{

    dissector_handle_t handle_minecraft = create_dissector_handle(dissect_minecraft, proto_minecraft);
    dissector_add_uint("tcp.port", 25565, handle_minecraft);
}

void plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_minecraft;
    plug.register_handoff = proto_reg_handoff_minecraft;
    proto_register_plugin(&plug);
}
