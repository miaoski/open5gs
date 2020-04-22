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
    ogs_pfcp_xact_commit(xact);
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
    ogs_pfcp_xact_commit(xact);

    ogs_timer_start(node->t_heartbeat,
            upf_timer_cfg(UPF_TIMER_HEARTBEAT)->duration);
}

void upf_n4_handle_session_establishment_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_session_establishment_request_t *req)
{
    upf_bearer_t *bearer = NULL;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("[UPF] Session Establishment Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    bearer = upf_default_bearer_in_sess(sess);
    ogs_assert(bearer);

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        ogs_pfcp_tlv_create_pdr_t *message = &req->create_pdr[i];
        ogs_pfcp_pdr_t *pdr = NULL;

        if (message->presence == 0)
            break;

        if (message->pdr_id.presence == 0) {
            ogs_warn("No PDR-ID");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            offending_ie_value = OGS_PFCP_PDR_ID_TYPE;
            break;
        }

        pdr = ogs_pfcp_pdr_find_or_add(&sess->pfcp, message->pdr_id.u16);
        ogs_assert(pdr);

        if (message->precedence.presence == 0) {
            ogs_warn("No Presence in PDR");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            offending_ie_value = OGS_PFCP_PRECEDENCE_TYPE;
            break;
        }

        if (message->pdi.presence == 0) {
            ogs_warn("No PDI in PDR");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            offending_ie_value = OGS_PFCP_PDI_TYPE;
            break;
        }

        if (message->pdi.source_interface.presence == 0) {
            ogs_warn("No Source Interface in PDI");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            offending_ie_value = OGS_PFCP_SOURCE_INTERFACE_TYPE;
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
                offending_ie_value = OGS_PFCP_F_TEID_TYPE;
                break;
            }

            if (message->outer_header_removal.presence == 0) {
                ogs_warn("No Outer Header Removal in PDI");
                cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
                offending_ie_value = OGS_PFCP_OUTER_HEADER_REMOVAL_TYPE;
                break;
            }

            memcpy(&pdr->f_teid, message->pdi.local_f_teid.data,
                    message->pdi.local_f_teid.len);
            pdr->f_teid.teid = be32toh(pdr->f_teid.teid);
            memcpy(&pdr->outer_header_removal,
                    message->outer_header_removal.data,
                    message->outer_header_removal.len);

            /* Setup UPF-N3-TEID */
            bearer->upf_n3_teid = pdr->f_teid.teid;
            ogs_hash_set(upf_self()->bearer_hash, &bearer->upf_n3_teid,
                    sizeof(bearer->upf_n3_teid), bearer);
        } else {
            ogs_error("Invalid Source Interface[%d] in PDR", pdr->src_if);
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            offending_ie_value = OGS_PFCP_SOURCE_INTERFACE_TYPE;
            break;
        }

        if (message->far_id.presence)
            ogs_pfcp_far_find_or_add(pdr, message->far_id.u32);
    }

    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_pfcp_sess_clear(&sess->pfcp);
        ogs_pfcp_send_error_message(xact, sess ? sess->pfcp.remote_n4_seid : 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                cause_value, offending_ie_value);
        return;
    }

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        ogs_pfcp_tlv_create_far_t *message = &req->create_far[i];
        ogs_pfcp_far_t *far = NULL;

        if (message->presence == 0)
            break;

        if (message->far_id.presence == 0) {
            ogs_warn("No FAR-ID");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
            break;
        }

        far = ogs_pfcp_far_find_by_id(&sess->pfcp, message->far_id.u32);
        if (!far) {
            ogs_error("Cannot find FAR-ID[%d] in PDR", message->far_id.u32);
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
            break;
        }

        if (message->apply_action.presence == 0) {
            ogs_warn("No Apply Action");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            offending_ie_value = OGS_PFCP_APPLY_ACTION_TYPE;
            break;
        }
        if (message->forwarding_parameters.
                destination_interface.presence == 0) {
            ogs_warn("No Destination Interface");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            offending_ie_value = OGS_PFCP_DESTINATION_INTERFACE_TYPE;
            break;
        }

        far->apply_action = message->apply_action.u8;
        far->dst_if = message->forwarding_parameters.destination_interface.u8;

        if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) { /* Downlink */
            int rv;
            ogs_ip_t ip;
            ogs_gtp_node_t *gnode = NULL;

            if (message->forwarding_parameters.
                    outer_header_creation.presence == 0) {
                ogs_warn("No Outer Header Creation in PDI");
                cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
                offending_ie_value = OGS_PFCP_OUTER_HEADER_CREATION_TYPE;
                break;
            }

            memcpy(&far->outer_header_creation,
                    message->forwarding_parameters.outer_header_creation.data,
                    message->forwarding_parameters.outer_header_creation.len);
            far->outer_header_creation.teid =
                be32toh(far->outer_header_creation.teid);

            /* Setup SGW-S5U-TEID */
            bearer->sgw_s5u_teid = far->outer_header_creation.teid;

            /* Setup GTP Node */
            rv = ogs_pfcp_outer_header_creation_to_ip(
                    &far->outer_header_creation, &ip);
            ogs_assert(rv == OGS_OK);

            gnode = ogs_gtp_node_find_by_ip(&upf_self()->sgw_s5u_list, &ip);
            if (!gnode) {
                gnode = ogs_gtp_node_add_by_ip(
                    &upf_self()->sgw_s5u_list, &ip, upf_self()->gtpu_port,
                    ogs_config()->parameter.no_ipv4,
                    ogs_config()->parameter.no_ipv6,
                    ogs_config()->parameter.prefer_ipv4);
                ogs_assert(gnode);

                rv = ogs_gtp_connect(
                        upf_self()->gtpu_sock, upf_self()->gtpu_sock6, gnode);
                ogs_assert(rv == OGS_OK);
            }
            OGS_SETUP_GTP_NODE(bearer, gnode);
        } else if (far->dst_if == OGS_PFCP_INTERFACE_CORE) {  /* Uplink */

            /* Nothing */

        } else {
            ogs_error("Invalid Destination Interface[%d] in FAR", far->dst_if);
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            offending_ie_value = OGS_PFCP_DESTINATION_INTERFACE_TYPE;
            break;
        }
    }

    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_pfcp_sess_clear(&sess->pfcp);
        ogs_pfcp_send_error_message(xact, sess ? sess->pfcp.remote_n4_seid : 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                cause_value, offending_ie_value);
        return;
    }

    upf_pfcp_send_session_establishment_response(xact, sess);
}

void upf_n4_handle_session_deletion_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_deletion_request_t *req)
{
    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("[UPF] Session Deletion Request");

    if (!sess) {
        ogs_warn("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    ogs_assert(sess);

    upf_pfcp_send_session_deletion_response(xact, sess);

    upf_sess_remove(sess);
}
