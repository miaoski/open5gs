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
#include "n4-build.h"

ogs_pkbuf_t *smf_n4_build_association_setup_request(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_request_t *req = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_debug("[SMF] Association Setup Request");

    req = &pfcp_message.pfcp_association_setup_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;
    
    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    req->cp_function_features.presence = 1;
    req->cp_function_features.u8 = smf_self()->function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_association_setup_response(uint8_t type,
        uint8_t cause)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_response_t *rsp = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_debug("[SMF] Association Setup Response");

    rsp = &pfcp_message.pfcp_association_setup_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    rsp->node_id.presence = 1;
    rsp->node_id.data = &node_id;
    rsp->node_id.len = node_id_len;

    rsp->cause.presence = 1;
    rsp->cause.u8 = cause;
    
    rsp->recovery_time_stamp.presence = 1;
    rsp->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    rsp->cp_function_features.presence = 1;
    rsp->cp_function_features.u8 = smf_self()->function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_session_establishment_request(
        uint8_t type, smf_sess_t *sess)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_session_establishment_request_t *req = NULL;

    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_urr_t *urr = NULL;
    ogs_pfcp_qer_t *qer = NULL;
    int i;

    ogs_pfcp_node_id_t node_id;
    ogs_pfcp_f_seid_t f_seid;
    ogs_pfcp_ue_ip_addr_t addr[OGS_MAX_NUM_OF_PDR];
    ogs_pfcp_outer_header_removal_t outer_header_removal[OGS_MAX_NUM_OF_PDR];
    ogs_pfcp_f_teid_t f_teid[OGS_MAX_NUM_OF_PDR];
    ogs_pfcp_outer_header_creation_t outer_header_creation[OGS_MAX_NUM_OF_FAR];
    char apn[OGS_MAX_NUM_OF_PDR][OGS_MAX_APN_LEN];
    int len;

    smf_bearer_t *bearer = NULL;

    ogs_debug("[SMF] Session Establishment Request");
    ogs_assert(sess);

    bearer = smf_default_bearer_in_sess(sess);
    ogs_assert(bearer);

    req = &pfcp_message.pfcp_session_establishment_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    /* Node ID */
    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = len;

    /* F-SEID */
    ogs_pfcp_sockaddr_to_f_seid(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            &f_seid, &len);
    f_seid.seid = htobe64(sess->pfcp.local_n4_seid);
    req->cp_f_seid.presence = 1;
    req->cp_f_seid.data = &f_seid;
    req->cp_f_seid.len = len;

    /* Create PDR */
    i = 0;
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        ogs_pfcp_tlv_create_pdr_t *message = &req->create_pdr[i];
        ogs_pfcp_far_t *far = NULL;
        smf_bearer_t *bearer = NULL;
        int j = 0;
        int len = 0;

        ogs_assert(message);
        ogs_assert(pdr);
        far = pdr->far;
        ogs_assert(far);
        bearer = pdr->bearer;
        ogs_assert(bearer);

        message->presence = 1;
        message->pdr_id.presence = 1;
        message->pdr_id.u16 = pdr->id;

        message->precedence.presence = 1;
        message->precedence.u32 = pdr->precedence;

        message->pdi.presence = 1;
        message->pdi.source_interface.presence = 1;
        message->pdi.source_interface.u8 = pdr->src_if;

        message->pdi.network_instance.presence = 1;
        message->pdi.network_instance.len = ogs_fqdn_build(
            apn[i], sess->pdn.apn, strlen(sess->pdn.apn));
        message->pdi.network_instance.data = apn[i];

        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE &&
            far->dst_if == OGS_PFCP_INTERFACE_ACCESS) { /* Dowklink */
            ogs_pfcp_paa_to_ue_ip_addr(&sess->pdn.paa, &addr[i], &len);
            addr[i].sd = OGS_PFCP_UE_IP_DST;

            message->pdi.ue_ip_address.presence = 1;
            message->pdi.ue_ip_address.data = &addr[i];
            message->pdi.ue_ip_address.len = len;

        } else if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS &&
                    far->dst_if == OGS_PFCP_INTERFACE_CORE) { /* Uplink */
            ogs_pfcp_sockaddr_to_f_teid(
                    bearer->upf_addr, bearer->upf_addr6,
                    &f_teid[i], &len);
            f_teid[i].teid = htobe32(bearer->upf_n3_teid);

            message->pdi.local_f_teid.presence = 1;
            message->pdi.local_f_teid.data = &f_teid[i];
            message->pdi.local_f_teid.len = len;

            if (sess->pdn.paa.pdn_type == OGS_GTP_PDN_TYPE_IPV4) {
                outer_header_removal[i].description =
                    OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4;
            } else if (sess->pdn.paa.pdn_type == OGS_GTP_PDN_TYPE_IPV6) {
                outer_header_removal[i].description =
                    OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IPV6;
            } else if (sess->pdn.paa.pdn_type == OGS_GTP_PDN_TYPE_IPV4V6) {
                outer_header_removal[i].description =
                    OGS_PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP;
            } else
                ogs_assert_if_reached();

            message->outer_header_removal.presence = 1;
            message->outer_header_removal.data =
                &outer_header_removal[i].description;
            message->outer_header_removal.len = 1;
        }
            
        if (pdr->far) {
            message->far_id.presence = 1;
            message->far_id.u32 = pdr->far->id;
        }

        for (j = 0; j < pdr->num_of_urr; j++) {
            if (j == 0) {
                message->urr_id.presence = 1;
                ogs_assert(pdr->urrs[j]);
                message->urr_id.u32 = pdr->urrs[j]->id;
            } else {
                ogs_error("[%d] No support multiple URR", j);
            }
        }
        for (j = 0; j < pdr->num_of_qer; j++) {
            if (j == 0) {
                message->qer_id.presence = 1;
                ogs_assert(pdr->qers[j]);
                message->qer_id.u32 = pdr->qers[j]->id;
            } else {
                ogs_error("[%d] No support multiple QER", j);
            }
        }

        i++;
    }

    /* Create FAR */
    i = 0;
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        ogs_pfcp_tlv_create_far_t *message = &req->create_far[i];
        ogs_pfcp_pdr_t *pdr = NULL;
        smf_bearer_t *bearer = NULL;

        ogs_assert(message);
        ogs_assert(far);
        pdr = far->pdr;
        ogs_assert(pdr);
        bearer = pdr->bearer;
        ogs_assert(bearer);

        message->presence = 1;
        message->far_id.presence = 1;
        message->far_id.u32 = far->id;

        message->apply_action.presence = 1;
        message->apply_action.u8 = far->apply_action;

        message->forwarding_parameters.presence = 1;
        message->forwarding_parameters.destination_interface.presence = 1;
        message->forwarding_parameters.destination_interface.u8 = far->dst_if;

        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE &&
            far->dst_if == OGS_PFCP_INTERFACE_ACCESS && /* Downlink */
            bearer->gnb_n3_teid) { /* gNB-N3-TEID is avaiable */
            ogs_pfcp_ip_to_outer_header_creation(
                    &bearer->gnb_ip, &outer_header_creation[i], &len);
            outer_header_creation[i].teid = htobe32(bearer->gnb_n3_teid);

            message->forwarding_parameters.outer_header_creation.presence = 1;
            message->forwarding_parameters.outer_header_creation.data =
                &outer_header_creation[i];
            message->forwarding_parameters.outer_header_creation.len = len;
        }

        i++;
    }

    /* Create URR */
    i = 0;
    ogs_list_for_each(&sess->pfcp.urr_list, urr) {
        ogs_pfcp_tlv_create_urr_t *message = &req->create_urr[i];

        ogs_assert(message);
        ogs_assert(urr);

        message->presence = 1;
        message->urr_id.presence = 1;
        message->urr_id.u32 = urr->id;

        i++;
    }

    /* Create QER */
    i = 0;
    ogs_list_for_each(&sess->pfcp.qer_list, qer) {
        ogs_pfcp_tlv_create_qer_t *message = &req->create_qer[i];

        ogs_assert(message);
        ogs_assert(qer);

        message->presence = 1;
        message->qer_id.presence = 1;
        message->qer_id.u32 = qer->id;

        i++;
    }

    /* PDN Type */
    req->pdn_type.presence = 1;
    req->pdn_type.u8 = sess->pdn.paa.pdn_type;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_session_deletion_request(
        uint8_t type, smf_sess_t *sess)
{
    ogs_pfcp_message_t pfcp_message;

    ogs_debug("[SMF] Session Establishment Request");
    ogs_assert(sess);

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}
