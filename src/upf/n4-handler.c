/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"
#include "timer.h"
#include "pfcp-path.h"
#include "n4-handler.h"

void upf_n4_handle_association_setup_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_request_t *req)
{
    ogs_assert(xact);
    upf_pfcp_send_association_setup_response(
            xact, OGS_PFCP_CAUSE_REQUEST_ACCEPTED);
}

void upf_n4_handle_association_setup_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_response_t *rsp)
{
    ogs_assert(xact);
}

void upf_n4_handle_heartbeat_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_heartbeat_request_t *req)
{
    ogs_assert(xact);
    ogs_pfcp_send_heartbeat_response(xact);
}

void upf_n4_handle_heartbeat_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_heartbeat_response_t *rsp)
{
    ogs_assert(xact);
    ogs_timer_start(node->t_heartbeat,
            upf_timer_cfg(UPF_TIMER_HEARTBEAT)->duration);
}

void upf_n4_handle_session_establishment_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_session_establishment_request_t *req)
{
    uint8_t cause_value = 0;
    int i;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("[UPF] Session Establishment Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND);
        return;
    }

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        ogs_pfcp_tlv_create_pdr_t *message = &req->create_pdr[i];
        ogs_pfcp_pdr_t *pdr = NULL;

        if (message->presence == 0)
            break;

        if (message->pdr_id.presence == 0) {
            ogs_warn("No PDR-ID");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            break;
        }

        pdr = ogs_pfcp_pdr_find_or_add(&sess->pfcp, message->pdr_id.u16);
        ogs_assert(pdr);

        if (message->precedence.presence == 0) {
            ogs_warn("No Presence in PDR");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            break;
        }

        if (message->pdi.presence == 0) {
            ogs_warn("No PDI in PDR");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            break;
        }

        if (message->pdi.source_interface.presence == 0) {
            ogs_warn("No Source Interface in PDI");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            break;
        }

        pdr->precedence = message->precedence.u32;
        pdr->src_if = message->pdi.source_interface.u8;

        /* APN(Network Instance) and UE IP Address
         * has already been processed in upf_sess_add() */

        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) {  /* Downlink */

            /* Nothing */

        } else if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) { /* Uplink */
            if (message->pdi.local_f_teid.presence == 0) {
                ogs_warn("No F-TEID in PDI");
                cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
                break;
            }

            if (message->outer_header_removal.presence == 0) {
                ogs_warn("No Outer Header Removal in PDI");
                cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
                break;
            }

            memcpy(&pdr->f_teid, message->pdi.local_f_teid.data,
                    message->pdi.local_f_teid.len);
            pdr->f_teid.teid = be32toh(pdr->f_teid.teid);
            memcpy(&pdr->outer_header_removal,
                    message->outer_header_removal.data,
                    message->outer_header_removal.len);
        } else {
            ogs_error("Invalid Source Interface[%d] in PDR", pdr->src_if);
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            break;
        }

        if (message->far_id.presence)
            ogs_pfcp_far_find_or_add(pdr, message->far_id.u32);
    }

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        ogs_pfcp_tlv_create_far_t *message = &req->create_far[i];
        ogs_pfcp_far_t *far = NULL;

        if (message->presence == 0)
            break;

        if (message->far_id.presence == 0) {
            ogs_warn("No FAR-ID");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            break;
        }

        far = ogs_pfcp_far_find_by_id(&sess->pfcp, message->far_id.u32);
        if (!far) {
            ogs_error("Cannot find FAR-ID[%d] in PDR", message->far_id.u32);
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            break;
        }

        if (message->apply_action.presence == 0) {
            ogs_warn("No Apply Action");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            break;
        }
        if (message->forwarding_parameters.
                destination_interface.presence == 0) {
            ogs_warn("No Destination Interface");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            break;
        }

        far->apply_action = message->apply_action.u8;
        far->dst_if = message->forwarding_parameters.destination_interface.u8;

        if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) { /* Downlink */
            if (message->forwarding_parameters.
                    outer_header_creation.presence == 0) {
                ogs_warn("No Outer Header Creation in PDI");
                cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
                break;
            }

            memcpy(&far->outer_header_creation,
                    message->forwarding_parameters.outer_header_creation.data,
                    message->forwarding_parameters.outer_header_creation.len);
            far->outer_header_creation.teid =
                be32toh(far->outer_header_creation.teid);

        } else if (far->dst_if == OGS_PFCP_INTERFACE_CORE) {  /* Uplink */

            /* Nothing */

        } else {
            ogs_error("Invalid Destination Interface[%d] in FAR", far->dst_if);
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            break;
        }
    }

    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_pfcp_sess_clear(&sess->pfcp);
        ogs_pfcp_send_error_message(xact, sess ? sess->pfcp.remote_n4_seid : 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE, cause_value);
        return;
    }
}
